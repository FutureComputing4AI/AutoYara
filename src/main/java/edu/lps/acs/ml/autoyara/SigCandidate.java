/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package edu.lps.acs.ml.autoyara;

import edu.lps.acs.ml.ngram3.alphabet.AlphabetGram;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 *
 * @author edraff
 */
public class SigCandidate
{    
    public enum Priority
    {
        ENTROPY
        {
            @Override
            int cmp(SigCandidate a, SigCandidate b, int[] curCoverage, int targetCover, double max_b_fp, double max_m_fp)
            {
                //negative b/c we are assuming higher entropy is better
                return -Double.compare(sigEntropy(a), sigEntropy(b));
            }
            
        },
        TOTAL_FP
        {
            @Override
            int cmp(SigCandidate a, SigCandidate b, int[] curCoverage, int targetCover, double max_b_fp, double max_m_fp)
            {
                max_b_fp = Math.max(max_b_fp, 1e-14);
                max_m_fp = Math.max(max_m_fp, 1e-14);
                double a_val = a.b_fp/max_b_fp + a.m_fp/max_m_fp;
                double b_val = b.b_fp/max_b_fp + b.m_fp/max_m_fp;
                return Double.compare(a_val, b_val);
            }
            
        },
        NEW_COVERAGE
        {
            @Override
            int cmp(SigCandidate a, SigCandidate b, int[] curCoverage, int targetCover, double max_b_fp, double max_m_fp)
            {
                long a_val = 0;
                long b_val = 0;
                
                a_val = a.coverage.stream().filter(v -> (curCoverage[v] < targetCover)).count();
                b_val = b.coverage.stream().filter(v -> (curCoverage[v] < targetCover)).count();
                
                //- b/c we want larger=better
                return -Long.compare(a_val, b_val);
            }
        },
        TOTAL_COVERAGE
        {
            @Override
            int cmp(SigCandidate a, SigCandidate b, int[] curCoverage, int targetCover, double max_b_fp, double max_m_fp)
            {
                //- b/c we want larger=better
                return -Integer.compare(a.coverage.size(), b.coverage.size());
            }
        }
        ;
        abstract int cmp(SigCandidate a, SigCandidate b, int[] curCoverage, int targetCover, double max_b_fp, double max_m_fp);
    }
    
    AlphabetGram signature;
    double b_fp;
    double m_fp;
    Set<Integer> coverage;
    double entropy = -1;

    @Override
    public boolean equals(Object obj)
    {
        return signature.equals(obj);
    }

    @Override
    public int hashCode()
    {
        return signature.hashCode();
    }

    public SigCandidate(AlphabetGram signature, double b_fp, double m_fp, Set<Integer> coverage)
    {
        this.signature = signature;
        this.b_fp = b_fp;
        this.m_fp = m_fp;
        this.coverage = coverage;
    }
    
    public static Set<SigCandidate> select(List<SigCandidate> candidates, int[] coverage, int targetCover, double max_b_fp, double max_m_fp, List<Priority> sortPriority)
    {
        Set<SigCandidate> selected = new HashSet<>();
        
        Set<SigCandidate> remainingOptions = new HashSet<>();
        remainingOptions.addAll(candidates);
        
        do
        {
            //First, lets go through and remove anyone that has NO increase in coverage
            remainingOptions.removeIf(s->
            {
                return s.coverage.stream().filter(i->coverage[i] < targetCover).count() == 0;
            });
            if(remainingOptions.isEmpty())
                break;
            
            SigCandidate best = Collections.min(remainingOptions, (SigCandidate a, SigCandidate b) ->
            {
                for(Priority p : sortPriority)
                {
                    int cmp = p.cmp(a, b, coverage, targetCover, max_b_fp, max_m_fp);
                    if(cmp != 0)
                        return cmp;
                }
                
                return 0;
            });
            
            remainingOptions.remove(best);
            selected.add(best);
            
            int coverageIncrease = 0;
            for(int indx : best.coverage)
                if(coverage[indx]++ < targetCover)
                    coverageIncrease++;
            
            if(coverageIncrease == 0)
                break;
            
            int c = targetCover;
            for(int x : coverage)
                c = Math.min(c, x);
            if(c >= targetCover)//min coverage is meet, break
                break;
        }
        while(!remainingOptions.isEmpty());
        
        return selected;
    }
    
    public double getEntropy()
    {
        if(entropy >= 0)
            return entropy;
        else
            return (entropy = sigEntropy(this));
    }
    
    public static double sigEntropy(SigCandidate a)
    {
        double[] counts = new double[256];
        int wildCards = 0;
        for(int i = 0; i < a.signature.size(); i++)
        {
            int indx = a.signature.getUnsigned(i);
            if(indx < counts.length)
                counts[indx]++;
            else//wild card, lets increment everyone by a partial to smooth it out
                wildCards++;
        }
        double entropy = 0;
        for(double count : counts)
        {
            //add smothing from wild card counts
            count += wildCards/counts.length;
            double p =  count/a.signature.size();

            if(p > 0)
                entropy += -p * Math.log(p)/Math.log(256);

        }
        return 8*entropy;
    }
}
