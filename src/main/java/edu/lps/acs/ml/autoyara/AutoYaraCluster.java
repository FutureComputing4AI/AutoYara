/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package edu.lps.acs.ml.autoyara;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.Parameter;
import com.beust.jcommander.ParameterException;
import com.beust.jcommander.converters.EnumConverter;
import edu.lps.acs.ml.ngram3.NGramGeneric;
import edu.lps.acs.ml.ngram3.alphabet.AlphabetGram;
import edu.lps.acs.ml.ngram3.utils.FileConverter;
import edu.lps.acs.ml.ngram3.utils.GZIPHelper;
import java.io.BufferedInputStream;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.nio.file.FileVisitOption;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.SortedSet;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentSkipListSet;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.BaseStream;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.Stream;
import jsat.SimpleDataSet;
import jsat.classifiers.DataPoint;
import jsat.clustering.HDBSCAN;
import jsat.clustering.VBGMM;
import jsat.clustering.biclustering.Bicluster;
import jsat.clustering.biclustering.SpectralCoClustering;
import jsat.linear.IndexValue;
import jsat.linear.SparseVector;
import jsat.linear.Vec;
import jsat.math.OnLineStatistics;
import jsat.utils.IntList;
import jsat.utils.concurrent.AtomicDouble;
import me.tongfei.progressbar.ProgressBar;

/**
 *
 * @author edraff
 */
public class AutoYaraCluster
{
    
    @Parameter(names={"--false-pos-benign", "-fpb"}, description = "The maximum false-positive rate among other benign files to consider using a given signature")
    double false_pos_b = 0.001;
    
    @Parameter(names={"--false-pos-malicious", "-fpm"}, description = "The maximum false-positive rate among other malicious files to consider using a given signature")
    double false_pos_m = 0.001;
    
    @Parameter(names={"--min-support-ratio", "-msr"}, description = "The minimum fraction of input files that must be covered by an n-gram for the n-gram to be considered as a potential signature")
    double support_ratio = 0.5;
    
    @Parameter(names={"--min-entropy", "-me"}, description = "The minimum entropy level required of an n-gram to be considered")
    double min_entropy = 1.0;
    
    @Parameter(names={"--max-filter-size", "-mfs"}, description = "Maximum filter size to use in signature creation. Larger values may improve rule quality, but increase RAM usage")
    int max_filter_size = 214748383;//default value is a prime that will use ~1 GB of RAM
    
    @Parameter(names={"--min-support-count", "-msc"}, description = "The minimum number of files that a potential signature must catch to be considered for inclusion in the larger rule.")
    int support_count = 2;
    
    /**
     * How many different rules do we want that cover the same input files?
     */
    @Parameter(names="--target-coverage", description = "During rule construction, how many sub-rules do you want to hit on each example? Larger values lead to larger rules.")
    int ways_covered = 1;
    
    
    @Parameter(names={"--to-keep", "-k"}, description="The number of n-gram candidates to create at every step of the process")
    int toKeep = 100000;
    
    @Parameter(names={"--benign", "-b"}, converter = FileConverter.class, description="Directory of bloom filters for benign files")
    File benign_bloom_dir = new File("benign-bytes");
    
    @Parameter(names={"--malicious", "-m"}, converter = FileConverter.class, description="Directory of bloom filters for Malicious Files")
    File malicious_bloom_dir = new File("malicious-bytes");
        
    @Parameter(names={"--fp-dirs", "-fpds"}, converter = FileConverter.class, required=false, 
        variableArity = true,
        description="Directories of files to check against for false positivesas part of evaluation. These will not be used to alter the rule generated.")
    List<File> fpEvalDirs = new ArrayList<>();
    
    @Parameter(names={"--tp-dirs", "-tpds"}, converter = FileConverter.class, required=false, 
        variableArity = true,
        description="Directories of files to check against for true positives as part of evaluation. These will not be used to alter the rule generated.")
    List<File> tpEvalDirs = new ArrayList<>();
    
    @Parameter(names={"--input-dir", "-i"}, converter = FileConverter.class, required=true, 
        variableArity = true,
        description="Directory of files to n-gram")
    List<File> inDir;
    
    @Parameter(names = "--save-all-rules",
        description = "If true, all yara rules created will be saved, rather "
                + "than just the best-found rule. This may be useful if the "
                + "selection heuristics do not actually select the best rule, or"
                + " you wish to do more testing / investigation. ")
    boolean save_all_rules = false;
    
    @Parameter(names = "--help", help = true)
    boolean help = false;
    
    @Parameter(names = "--silent")
    boolean silent = false;
    
    @Parameter(names = "--print-rules", description = "If true, print out the yara-rules onto the command line.")
    boolean print_rules = false;
    
    @Parameter(names={"--out", "-o"}, converter = FileConverter.class, 
        description="Output file/directory. If only one rule is to be created, "
                + "and output is a directory, the name will be infered from the "
                + "first input file. If multiple rule options are to be saved, "
                + "the first directory in the given path will be used. Multiple "
                + "rules will be saved with a pre-fix of the rule size type. By "
                + "default, rules are writen out to the current directory. ")
    File out_file = null;
    
    public static void main(String... args) throws IOException
    {
        System.out.println("AutoYara version " + Version.pomVersion + ", compile date: " + Version.buildTime);
        AutoYaraCluster main = new AutoYaraCluster();

        JCommander optionParser = JCommander.newBuilder()
                .addObject(main)
                .build();
        try {
            optionParser.parse(args);
        } catch(ParameterException ex) {
            optionParser.usage();
            return;
        }
        
        if(main.help)
        {
            optionParser.usage();
            return;
        }

        main.run();
    }
    
    public static int log2( int bits )
    {
        if( bits == 0 )
            return 0; 
        return 31 - Integer.numberOfLeadingZeros(bits);
    }
    
    public void run() throws IOException
    {
        if(out_file == null)
            out_file = new File(inDir.get(0).getName() + ".yara");
        final String name = out_file.getName().replace(".yara", "");
        final File out_dir;
        if(out_file.isDirectory())
        {
            out_dir = out_file;
            out_file = new File(out_dir, name);
        }
        else
            out_dir = out_file.getParentFile();
        
        //sort from high to low
        SortedSet<Integer> bloomSizes = new ConcurrentSkipListSet<>((a, b) -> a.compareTo(b));
        collectBloomSizes(bloomSizes, benign_bloom_dir, malicious_bloom_dir);
        
        Map<Integer, CountingBloom> ben_blooms = collectBloomFilters(benign_bloom_dir);
        Map<Integer, CountingBloom> mal_blooms = collectBloomFilters(malicious_bloom_dir);
        
        /////////////////////////
        //we now have our filters
        ////////////////////////

        List<Path> targets = getAllChildrenFiles(inDir);
        
        
        /**
         * A n-gram must occur in at least this many files to be a candidate for selection
         */
        
        /////////////
        //, lets find some potential yara rules!
        /////////////
        
        final Collection<YaraRuleContainerConjunctive> best_rule = new ArrayList();
        final AtomicDouble best_rule_coverage = new AtomicDouble(0);
        /**
         * Whether or not we meet the goal of having at least 5 terms/features 
         * in conjunctions
         */
        final AtomicBoolean meets_min_desired_coverage = new AtomicBoolean(false);
        final AtomicInteger best_rule_gram_size = new AtomicInteger(0);
        
        final Map<Set<Integer>, SigCandidate> multi_gram_working_set = new HashMap<>();
        
        bloomSizes.stream().forEach(gram_size->
        {

            if(best_rule_coverage.get() >= 1.0 && meets_min_desired_coverage.get())
                return;//STOP, you can't get any better
            
            List<SigCandidate> finalCandidates = buildCandidateSet(targets, gram_size, ben_blooms, mal_blooms, 
                                       max_filter_size, toKeep, silent, Math.max(false_pos_b, false_pos_m));
            
            Set<Integer> alreadyFrailedOn = new HashSet<>();
            for(SpectralCoClustering.InputNormalization norm : SpectralCoClustering.InputNormalization.values())
            {
                Set<Integer> rows_covered = new HashSet<>();
                
                YaraRuleContainerConjunctive yara= buildRule(finalCandidates, targets, rows_covered, name, norm,
                                                            gram_size, alreadyFrailedOn);

                double fp_rate = fpEvalDirs.isEmpty() ? 0 : addMatchEval("False Positives:", fpEvalDirs, yara);
                double tp_rate = tpEvalDirs.isEmpty() ? 0 : addMatchEval("True Positives:", tpEvalDirs, yara);
                double input_tp_rate = addMatchEval("Input TP Rate:", inDir, yara);

                if(print_rules)
                {
                    System.out.println(yara);
    //                System.out.println("Selected " + toUse.size() + " grams to cover " + this_coverage);
                }

                if(save_all_rules)
                {                
                    try(BufferedWriter bw = new BufferedWriter(new FileWriter(new File(out_dir, name + "_" + gram_size  + "_" + norm.name() + ".yara"))))
                    {
                        bw.write(yara.toString());
                    }
                    catch (IOException ex)
                    {
                        Logger.getLogger(AutoYaraCluster.class.getName()).log(Level.SEVERE, null, ex);
                    }
                }
		
                int log_diff_gram_size = log2(gram_size)-log2(best_rule_gram_size.get());
                boolean this_rule_strong = yara.minConjunctionSize() >= 5;
                double penalty = Math.min(yara.minConjunctionSize()/5.0, 1);
                
                if(input_tp_rate*penalty > best_rule_coverage.get() + log_diff_gram_size/100.0)//give a slight favor to smaller rules!
                {
                    best_rule.clear();
                    best_rule.add(yara);

                    best_rule_coverage.set(input_tp_rate*penalty);
                    best_rule_gram_size.set(gram_size);
                    meets_min_desired_coverage.set(this_rule_strong);
                }
            }
        });
        
        if(best_rule.isEmpty())
        {
            System.out.println("Could not create yara-rule that matched constraints :(");
            return;
        }
        
        if(!silent)
            System.out.println("Saving rule to " + out_file.getAbsolutePath());
        try(BufferedWriter bw = new BufferedWriter(new FileWriter(out_file)))
        {
            YaraRuleContainerConjunctive yara = best_rule.stream().findFirst().get();
            bw.write(yara.toString());
        }
        
        
    }
    
    static public List<Path> getAllChildrenFiles(Path... sourceDirs)
    {
        return getAllChildrenFiles(Arrays.asList(sourceDirs).stream().map(f->f.toFile()).collect(Collectors.toList()));
    }

    static public List<Path> getAllChildrenFiles(File... sourceDirs)
    {
        return getAllChildrenFiles(Arrays.asList(sourceDirs));
    }
    
    static public List<Path> getAllChildrenFiles(List<File> sourceDirs)
    {

        
        List<Path> targets = sourceDirs.stream().flatMap(f->
        {
            try
            {
                return Files.walk(f.toPath(), FileVisitOption.FOLLOW_LINKS).filter(Files::isRegularFile);
            }
            catch (IOException ex)
            {
                Logger.getLogger(AutoYaraCluster.class.getName()).log(Level.SEVERE, null, ex);
                return new ArrayList<Path>().stream();
            }
        }).collect(Collectors.toList());
        return targets;
    }
    
    /**
     * This method does the work to create a final list of n-gram candidates to be used in the rule creation process
     * @param targets the list of files to create a rule that matches
     * @param gram_size the n-gram size to use
     * @param ben_blooms the set of known benign bloom filters
     * @param mal_blooms the set of known malicious bloom filters
     * @return a set of signature candidate objects
     */
    public static List<SigCandidate> buildCandidateSet(List<Path> targets, int gram_size, 
        Map<Integer, CountingBloom> ben_blooms, Map<Integer, CountingBloom> mal_blooms,
        long max_filter_size, int toKeep, boolean silent, double fp_rate)
    {
        long totalbytes = targets.stream().mapToLong(p->
        {
            try
            {
                return Files.size(p);
            }
            catch (IOException ex)
            {
                Logger.getLogger(AutoYaraCluster.class.getName()).log(Level.SEVERE, null, ex);
                return 0L;
            }
        }).sum();
        
        NGramGeneric ngram = new NGramGeneric();
        ngram.setAlphabetSize(256);
        long filter_size = Math.min(totalbytes/4, max_filter_size);
        ngram.setFilterSize((int) filter_size);
        ngram.setGramSize(gram_size);
        ngram.setTooKeep(toKeep);

        ngram.init();

        wrap(targets.parallelStream(), "Finding candidate " + gram_size  +"-byte sequences", silent)
            .forEach(p->
            {
                try(InputStream in = new BufferedInputStream(GZIPHelper.getStream(Files.newInputStream(p))))
                {
                    ngram.hashCount(in);
                }
                catch (IOException | InterruptedException ex)
                {
                    Logger.getLogger(AutoYaraCluster.class.getName()).log(Level.SEVERE, null, ex);
                }
            });


        ngram.finishHashCount();

        wrap(targets.parallelStream(), "Finding final " + gram_size  +"-byte sequences", silent)
            .forEach(p->
            {
                try(InputStream in = new BufferedInputStream(GZIPHelper.getStream(Files.newInputStream(p))))
                {
                    ngram.exactCount(in);
                }
                catch (IOException ex)
                {
                    Logger.getLogger(AutoYaraCluster.class.getName()).log(Level.SEVERE, null, ex);
                }
            });

        Map<AlphabetGram, AtomicInteger> final_candidates = ngram.finishExactCount();
        //We now have a set of potential n-grams to use as yara rules. 
        //Lets go through and remove non-vaiable candidates 

        CountingBloom ben_bloom = ben_blooms.get(gram_size);
        CountingBloom mal_bloom = mal_blooms.get(gram_size);
        //your FP rates are too high! Remove them!
        final_candidates.entrySet().removeIf(e->
        {
            AlphabetGram candidate =  e.getKey();
            
            int num_00_ff = 0;
            for(int i = 0; i < candidate.size(); i++)
                if(candidate.get(i) == 0x00 || candidate.get(i) == 0xFF)
                    num_00_ff++;
            if(num_00_ff > candidate.size()/2)
                return true;
            
            double ben_fp = ben_bloom.get(candidate) / (double) ben_bloom.divisor;
            double mal_fp = mal_bloom.get(candidate) / (double) mal_bloom.divisor;
            return ben_fp > fp_rate || mal_fp > fp_rate;
        });

        //Now we need to scan the data again. We have rough hit rates
        //but some of our input rules may be very corelated with eachother
        //so lets figure that out 

        Map<AlphabetGram, Set<Integer>> files_occred_in = new HashMap<>();
        final_candidates.keySet().forEach(k->files_occred_in.put(k, new ConcurrentSkipListSet()));

        AtomicInteger simpleID = new AtomicInteger();
        wrap(targets.parallelStream(), "Determining co-occurance of " + gram_size  +"-byte sequences", silent)
            .forEach(p->
            {
                try(InputStream in = new BufferedInputStream(GZIPHelper.getStream(Files.newInputStream(p))))
                {
                    ngram.incrementConuts(in, simpleID.getAndIncrement(), files_occred_in);
                }
                catch (IOException ex)
                {
                    Logger.getLogger(AutoYaraCluster.class.getName()).log(Level.SEVERE, null, ex);
                }
            });


        Map<SigCandidate, Set<Integer>> cur_working_set = new ConcurrentHashMap<>(files_occred_in.size());

        //Populate current working set to try and filter down. 
        files_occred_in.entrySet().parallelStream().forEach(e->
        {
            AlphabetGram candidate =  e.getKey();
            double ben_fp = ben_bloom.get(candidate) / (double) ben_bloom.divisor;
            double mal_fp = mal_bloom.get(candidate) / (double) mal_bloom.divisor;
            cur_working_set.put(new SigCandidate(candidate, ben_fp, mal_fp, e.getValue()), e.getValue());
        });


        List<SigCandidate> sigCandidates = Collections.EMPTY_LIST;
        sigCandidates = cur_working_set.keySet().parallelStream()
                .filter(s->s.getEntropy()>1.0)
                .collect(Collectors.toList());

        if(sigCandidates.isEmpty())//We need to try a different n-gram size
            return Collections.EMPTY_LIST;

        //Create a final candidate list, remove signatures that have 100% correlation with others
        List<SigCandidate> finalCandidates = new ArrayList<>();
        Map<Set<Integer>, List<SigCandidate>> coverageGrouped = new ConcurrentHashMap<>();
        //done i parallel b/c hashing cost on the Set<Integer> can be a bit pricy
        sigCandidates.parallelStream().forEach(s->
        {
            //slightly odd call structure ensures we don't fall victim to any race condition
            coverageGrouped.putIfAbsent(s.coverage, new ArrayList<>());
            List<SigCandidate> storage = coverageGrouped.get(s.coverage);
            
            //copute entropy now in parallel for use later
            synchronized(storage)
            {
                storage.add(s);
            }
        });
        
        for(List<SigCandidate> group : coverageGrouped.values())
        {
            //Pick gram with maximum entropy
            if(!group.isEmpty())
                finalCandidates.add(Collections.max(group, (SigCandidate arg0, SigCandidate arg1) -> Double.compare(arg0.getEntropy(), arg1.getEntropy())));
        }
        
        return finalCandidates;
    }

    /**
     * 
     * @param header A string to add to the begining of the comment for the results
     * @param evalDirs the list of directories to perform evaluations on
     * @param yara the yara rule to evaluate, for which we will add comments to the Yara rule with the rules on each directory
     * @return the match rate against all files in the given directories
     */
    public static double addMatchEval(String header, List<File> evalDirs, YaraRuleContainerConjunctive yara)
    {
        //Lets check against false positive directories to make sure all is kosher in the world
        if(!evalDirs.isEmpty())
        {
            double numer = 0;
            double denom = 0;
            StringBuilder comment = new StringBuilder();
            comment.append(header).append("\n");
            
            /**
             * If there are sub folders, we will add comments to delineate by 
             * folder what the hits where. If this is just a list of files, we 
             * will change naming style of the comment. 
             */
            boolean added_based_on_folders = false;
            List<File> looseFiles = new ArrayList<>();
            for(File dir : evalDirs)
            {
                if(dir.isFile())
                {
                    looseFiles.add(dir);
                    continue;
                }
                
                try
                {
                    List<Path> toTest = Files.walk(dir.toPath(), FileVisitOption.FOLLOW_LINKS)
                            .filter(Files::isRegularFile).collect(Collectors.toList());
                    for(Path p : toTest)
                        looseFiles.add(p.toFile());
                    if(!toTest.isEmpty())
                        continue;
                    comment.append(dir.getAbsoluteFile() + ":");
                    List<Path> fps = toTest.parallelStream().filter(p->
                    {
                        try(BufferedInputStream bis = new BufferedInputStream(GZIPHelper.getStream(Files.newInputStream(p))))
                        {
                            return yara.match(bis);
                        }
                        catch (IOException ex)
                        {
                            return false;
                        }
                    }).collect(Collectors.toList());
                    
                    denom += toTest.size();
                    numer += fps.size();
                    comment.append(fps.size() + "/" + toTest.size() + "\n");
                    added_based_on_folders = true;
                    if(!fps.isEmpty())
                    {
                        //TODO, write out the files that we FPd on
                    }
                    
                }
                catch (IOException ex)
                {
                    Logger.getLogger(AutoYaraCluster.class.getName()).log(Level.SEVERE, null, ex);
                }
                
                yara.addComment(comment.toString());
            }
            
            //The loose files now get done in one go
            List<File> fps = looseFiles.parallelStream().filter(p->
            {
                try(BufferedInputStream inputStream = new BufferedInputStream(GZIPHelper.getStream(Files.newInputStream(p.toPath()))))
                {
                    return yara.match(inputStream);
                }
                catch (IOException ex)
                {
                    return false;
                }
            }).collect(Collectors.toList());

            denom += looseFiles.size();
            numer += fps.size();
            if(added_based_on_folders)
                comment.append("Other Files:");
            //else, its not "other", but all
            comment.append(fps.size() + "/" + looseFiles.size() + "\n");
            if(!fps.isEmpty())
            {
                //TODO, write out the files that we FPd on
            }
            yara.addComment(comment.toString());
            
            return numer/denom;
        }
        else
            return 1.0;
    }

    static public YaraRuleContainerConjunctive buildRule(List<SigCandidate> finalCandidates, List<Path> targets, Set<Integer> rows_covered, final String name, SpectralCoClustering.InputNormalization normalization, int gram_size, Set<Integer> alreadyFailedOn)
    {
        int D = finalCandidates.size();
        int N = targets.size();
        YaraRuleContainerConjunctive yara = new YaraRuleContainerConjunctive(N, name);
        if(D == 0)//Nothing to do :( 
            return yara;
//        System.out.println("We have " +  D + " potential features");
        //Lets build a dataset object representing the files and which signatures (features) occured in each
        List<Vec> dataRep = new ArrayList<>();
        for(int i = 0; i < N; i++)
            dataRep.add(new SparseVector(D, 4));
        for(int d = 0; d < D; d++)
        {
            for(int i : finalCandidates.get(d).coverage)
                dataRep.get(i).set(d, 1.0);
        }
        SimpleDataSet sigDataset = new SimpleDataSet(dataRep.stream().map(v->new DataPoint(v)).collect(Collectors.toList()));
        List<Set<Integer>> conjuction_sets = new ArrayList<>();
        //            
        int min_rows = 5;
        int min_features = 5;
        List<List<Integer>> row_clusters = new ArrayList<>();
        List<List<Integer>> col_clusters = new ArrayList<>();
        
        if(D == 1)//not much to do... 
        {
            col_clusters.add(IntList.range(D));
            row_clusters.add(IntList.range(N));
        }
        else
        {
            try
            {
                getCoClustering(sigDataset, row_clusters, col_clusters, normalization);
            }
            catch(Exception ex)
            {
            }
            
            if(!alreadyFailedOn.contains(gram_size) && (row_clusters.isEmpty() || col_clusters.isEmpty()))
            {
                alreadyFailedOn.add(gram_size);
                row_clusters.clear();
                col_clusters.clear();
                try
                {
                    getCoClusteringH(sigDataset, row_clusters, col_clusters);
                }
                catch(Exception ex2)
                {
                    //we give up
                    row_clusters.clear();
                    col_clusters.clear();
                }
            }
        }
        
        int max_row_size_seen = row_clusters.stream().mapToInt(r->r.size()).max().orElse(1);
        if(max_row_size_seen < min_rows)
            min_rows = max_row_size_seen;
        List<int[]> feature_counts_all = new ArrayList<>();
        //in ordr to know the true minimum count, we need to first perform a 
        //filtering based on the counts, becasue we will perform a filtering 
        //later. So lets collect this information now
        for(List<Integer> row_c : row_clusters)
        {
            int[] feature_counts = new int[D];
            for(int i: row_c)
                for(IndexValue iv : sigDataset.getDataPoint(i).getNumericalValues())
                    feature_counts[iv.getIndex()]++;
            feature_counts_all.add(feature_counts);
        }
        int max_features_seen = IntStream.range(0, row_clusters.size()).map(c->
        {
            int C_size = row_clusters.get(c).size();
            int[] feature_counts = feature_counts_all.get(c);
            return (int)col_clusters.get(c).stream().filter(j->feature_counts[j] >= 0.5*C_size).count();
        }).max().orElse(1);
        if(max_features_seen < min_features)//if we didn't mean the min, subtract an extra b/c otherwise we need the min count to hit the max rows, which is not likely
            min_features = Math.max(max_features_seen-1, 1);
        
        for (int c = 0; c < row_clusters.size(); c++)
        {
            int C_size = row_clusters.get(c).size();
            if(C_size < min_rows)
                continue;
            int[] feature_counts = feature_counts_all.get(c);

            //First, lets remove obvious non-starters. You need to appear in at least half the files in your cluster
            Set<Integer> selected_features = new HashSet<>(col_clusters.get(c));

            //We are only going to consider features that occur in >= 50% of this cluster
            selected_features.removeIf(j-> feature_counts[j] < 0.5*C_size);

            if(selected_features.size() < min_features)
                continue;

            conjuction_sets.add(selected_features);


            //how many files have at least X of these features?
            List<Integer> file_occurance_counts = new ArrayList<>();
            rows_covered.addAll(row_clusters.get(c));
            for(int i : row_clusters.get(c))
            {
                int nnz_in_bic = 0;
                for(IndexValue iv : dataRep.get(i))
                    if(selected_features.contains(iv.getIndex()) && iv.getValue() > 0)
                        nnz_in_bic++;
                file_occurance_counts.add(nnz_in_bic);
            }

            Collections.sort(file_occurance_counts);
            OnLineStatistics right_portion = new OnLineStatistics();
            for(int count : file_occurance_counts)
                right_portion.add(count);

            OnLineStatistics left_portion = new OnLineStatistics();
            double min_score = Double.POSITIVE_INFINITY;
            int indx = 0;
            for(int i = 0; i < file_occurance_counts.size()-1; i++)
            {
                int count_i = file_occurance_counts.get(i);
                left_portion.add(count_i, 1.0);
                right_portion.remove(count_i, 1.0);
                //same value check, keep shifting while the value stays the same
                while(i < file_occurance_counts.size()-1 && count_i == file_occurance_counts.get(i+1))
                {
                    i++;
                    left_portion.add(count_i, 1.0);
                    right_portion.remove(count_i, 1.0);
                }


                double cur_score = left_portion.getVarance()*left_portion.getSumOfWeights()
                        + right_portion.getVarance() * right_portion.getSumOfWeights();

                if(cur_score < min_score)
                {
                    indx = i;
                    min_score = cur_score;
                }
            }


            int count_min = file_occurance_counts.get(Math.min(indx+1, file_occurance_counts.size()-1));

            yara.addSignature(count_min, selected_features.stream().map(i->finalCandidates.get(i)).collect(Collectors.toSet()));

        }
        return yara;
    }
    
    private static void getCoClusteringH(SimpleDataSet sigDataset, List<List<Integer>> rows, List<List<Integer>> cols)
    {
        int D = sigDataset.getNumFeatures();
        int[] cluster_assingments = getClustering(sigDataset);
        int num_clusters = IntStream.of(cluster_assingments).max().getAsInt()+1;
            for (int c = 0; c < num_clusters; c++)
            {
                IntList row = new IntList();

                int[] feature_counts = new int[D];
                for(int i = 0; i < cluster_assingments.length; i++)
                    if(cluster_assingments[i] == c)
                    {
                        row.add(i);
                        for(IndexValue iv : sigDataset.getDataPoint(i).getNumericalValues())
                            feature_counts[iv.getIndex()]++;
                    }
                final int n_c =row.size();
                
                //First, lets remove obvious non-starters. You need to appear in at least half the files in your cluster
                Set<Integer> selected_features = IntStream.range(0, D)
                        .filter(j->feature_counts[j] >= n_c*0.5)
                        .boxed().collect(Collectors.toSet());
                
                if(selected_features.isEmpty())
                    continue;
                //TODO, what if no-one satisfied the above?
                
                //Lets reduce to a set of features that occur at least as frequently as the median count
                int[] counts = selected_features.stream().mapToInt(i->feature_counts[i]).toArray();
                Arrays.sort(counts);
                int median_feature_count = counts[counts.length/2];
                selected_features.removeIf(j->feature_counts[j] < median_feature_count);
                
                
                if(!selected_features.isEmpty())
                {
                    
                }

                rows.add(row);
                cols.add(new IntList(selected_features));
                
            }
    }
    
    static private void getCoClustering(SimpleDataSet sigDataset, List<List<Integer>> rows, List<List<Integer>> cols, SpectralCoClustering.InputNormalization norm)
    {
        SpectralCoClusteringVBMM bc = new SpectralCoClusteringVBMM();
        bc.inputNormalization = norm;
        bc.bicluster(sigDataset, true, rows, cols);
//        SpectralCoClustering bc = new SpectralCoClustering();
//        bc.setBaseClusterAlgo(new VBGMM());
//        bc.bicluster(sigDataset, true, rows, cols);
//        int min_pts = 15;
//        while(rows.isEmpty() && min_pts > 3)
//        {
//            System.out.println("trying " + min_pts);
//            bc.setBaseClusterAlgo(new HDBSCAN(min_pts--));
//            bc.bicluster(sigDataset, true, rows, cols);
//        }
    }

    private static int[] getClustering(SimpleDataSet sigDataset)
    {
        int[] designations = new int[sigDataset.size()];
        Arrays.fill(designations, -1);
        //Ok, lets do some clustering and try to find good feature set intersections
        for (int min_pts : new int[]{15, 10, 5})
        {
            HDBSCAN cluster_algo = new HDBSCAN(min_pts);
            cluster_algo.cluster(sigDataset, true, designations);
            int clusters = IntStream.of(designations).max().getAsInt()+1;
            if(clusters > 0)
                return designations;
        }
        return designations;
    }
    
    static public <T, S extends BaseStream<T, S>> Stream<T> wrap(Stream<T> stream, String task, boolean silent)
    {
        if(silent)
            return stream;
        else
            return ProgressBar.wrap(stream, task);
    }
    
    public <T, S extends BaseStream<T, S>> Stream<T> wrap(Stream<T> stream, String task)
    {
        return wrap(stream, task, silent);
    }

    /**
     * 
     * @param bloom_dir the directory that contains bloom filters
     * @return a map where the key is the n-gram size, and the value is the corresponding bloom filter. 
     * @throws IOException 
     */
    public static Map<Integer, CountingBloom>  collectBloomFilters(File bloom_dir) throws IOException
    {
        Map<Integer, CountingBloom> blooms = new HashMap<>();
        Files.walk(bloom_dir.toPath(), FileVisitOption.FOLLOW_LINKS)
                //just bloom filters
                .filter(p->p.getFileName().toString().endsWith(".bloom"))
                .forEach(p->
                {
                    try(ObjectInputStream ois = new ObjectInputStream(new BufferedInputStream(Files.newInputStream(p))))
                    {
                        CountingBloom bloom = (CountingBloom) ois.readObject();
                        int gram_size = bloomNameToGramSize(p.getFileName().toString());
                        blooms.put(gram_size, bloom);
                    }
                    catch (IOException | ClassNotFoundException ex)
                    {
                        Logger.getLogger(AutoYaraCluster.class.getName()).log(Level.SEVERE, null, ex);
                    }
                });
        return blooms;
    }

    public static void collectBloomSizes(SortedSet<Integer> bloomSizes, File... dirs) throws IOException
    {
        for(File dir : dirs)
            Files.walk(dir.toPath(), FileVisitOption.FOLLOW_LINKS)
                    //just bloom filters
                    .map(p->p.getFileName().toString())
                    .filter(s->s.endsWith(".bloom"))
                    .filter(s->s.matches(".+_\\d+\\.bloom"))//name is formated as "name_size.bloom"
                    .mapToInt(s->bloomNameToGramSize(s))
                    .forEach(bloomSizes::add);
    }

    public static int bloomNameToGramSize(String s) throws NumberFormatException
    {
        String[] tmp = s.replace(".bloom", "").split("_");
        return Integer.parseInt(tmp[tmp.length-1]);
    }
}
