/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package edu.lps.acs.ml.autoyara;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.Parameter;
import com.beust.jcommander.ParameterException;
import edu.lps.acs.ml.ngram3.NGramGeneric;
import edu.lps.acs.ml.ngram3.alphabet.AlphabetGram;
import edu.lps.acs.ml.ngram3.utils.FileConverter;
import edu.lps.acs.ml.ngram3.utils.GZIPHelper;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectOutputStream;
import java.nio.file.FileVisitOption;
import java.nio.file.Files;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.Collectors;
import static java.lang.Math.*;
import java.util.stream.Stream;
import me.tongfei.progressbar.ProgressBar;
import me.tongfei.progressbar.ProgressBarStyle;

/**
 *
 * @author edraff
 */
public class Bytes2Bloom
{
    @Parameter(names="--filter-size")
    int filterSize = Integer.MAX_VALUE - 18;
    
    @Parameter(names={"--false-pos-rate", "-fp"})
    double false_pos = 0.01;
    
    @Parameter(names={"--progress-bar", "-pb"})
    boolean pb_bars = false;
    
    @Parameter(names="--name", description="NGrams to keep")
    String out_name;
    
    @Parameter(names={"--too-keep", "-k"}, required=true, description="NGrams to keep")
    int tooKeep;
    @Parameter(names={"--ngram-size", "-n"}, required=true, description="Sizes of ngrams")
    List<Integer> gramSizes;
    
    @Parameter(names={"--input-dir", "-i"}, converter = FileConverter.class, required=true, description="Directory of files to n-gram")
    File inDir;
    
    @Parameter(names={"--out", "-o"}, converter = FileConverter.class, required=true, description="Output file")
    File outDir;
            
    public static void main(String... args) throws IOException
    {
        System.out.println("AutoYara version " + Version.pomVersion + ", compile date: " + Version.buildTime);
        Bytes2Bloom main = new Bytes2Bloom();
        
        JCommander optionParser = JCommander.newBuilder()
            .addObject(main)
            .build();
        try {
            optionParser.parse(args);
        } catch(ParameterException ex) {
            optionParser.usage();
            return;
        }
        
        
        main.run();
    }
    
    public void run() throws IOException
    {
        if(out_name == null)
            out_name = inDir.getName();
        
        final int filter_slots = (int) ceil((tooKeep * log(false_pos)) / log(1 / pow(2, log(2))));
        final int filter_hashes = (int) round((filter_slots / (double)tooKeep) * log(2));
        
        /**
         * All the files we will be running n-grams over
         */
        List<File> allFiles = Files.walk(inDir.toPath(), FileVisitOption.FOLLOW_LINKS)
                .parallel()
                .filter(p->!Files.isDirectory(p))
                .map(p->p.toFile())
                .collect(Collectors.toList());
        
        gramSizes.forEach(gram_size->
        {
            NGramGeneric ngram = new NGramGeneric();
            ngram.setAlphabetSize(256);
            ngram.setFilterSize(filterSize);
            ngram.setGramSize(gram_size);
            ngram.setTooKeep(tooKeep);
            
            System.out.println("Starting " + gram_size + "-grams of " + allFiles.size() + " files...");
            
            ngram.init();
            
            Stream<File> stream = allFiles.parallelStream();

            if(pb_bars)
                stream = ProgressBar.wrap(stream, "Hash-Pass");
            
            stream.forEach(f->
            {
                try(InputStream is = new BufferedInputStream(GZIPHelper.getStream(new FileInputStream(f))))
                {
                    ngram.hashCount(is);
                }
                catch (IOException | InterruptedException ex)
                {
                    Logger.getLogger(Bytes2Bloom.class.getName()).log(Level.SEVERE, null, ex);
                }
                
            });
            
            System.out.println("Finding top-k hashes");
            ngram.finishHashCount();
            
            stream = allFiles.parallelStream();
            if(pb_bars)
                stream = ProgressBar.wrap(stream, "Exact-Pass");
            stream.forEach(f->
            {
                try(InputStream is = new BufferedInputStream(GZIPHelper.getStream(new FileInputStream(f))))
                {
                    ngram.exactCount(is);
                }
                catch (IOException ex)
                {
                    Logger.getLogger(Bytes2Bloom.class.getName()).log(Level.SEVERE, null, ex);
                }
                
            });
            
            Map<AlphabetGram, AtomicInteger> found_grams = ngram.finishExactCount();
            CountingBloom bloom = new CountingBloom(filter_slots, filter_hashes);
            bloom.divisor = allFiles.size();
            
            for(Map.Entry<AlphabetGram, AtomicInteger> entry : found_grams.entrySet())
                bloom.put(entry.getKey(), entry.getValue().get());
            
            try(ObjectOutputStream out = new ObjectOutputStream(
                    new BufferedOutputStream(new FileOutputStream(
                            new File(outDir, out_name + "_" + gram_size + ".bloom")))))
            {
                out.writeObject(bloom);
            }
            catch (IOException ex)
            {
                Logger.getLogger(Bytes2Bloom.class.getName()).log(Level.SEVERE, null, ex);
            }
        
        });
    }
}
