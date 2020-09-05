/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package edu.lps.acs.ml.autoyara;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.util.Random;

/**
 *
 * @author edraff
 */
public class CountingBloom implements Serializable
{
    static final long serialVersionUID = -5941164052778931036L;
    
    /**
     * default base value should be good to reach 2^32
     */
    double base = 1.090878326190223750496427194244941608437246127397209913749;
    double log_base = 0.086983175599679411377848736810437843836925507056973208359;
    byte[] counts;
    
    int added = 0;
    int divisor = 0;

    int[] hashSeeds;

    public CountingBloom()
    {
        this(0, 0);
    }

    public int getNumEntries()
    {
        return added;
    }
    
    public CountingBloom(int slots, int hashFunctions)
    {
        counts = new byte[slots];
        Random r = new Random(System.currentTimeMillis());
        hashSeeds = new int[hashFunctions];
        for (int i = 0; i < hashFunctions; ++i)
            hashSeeds[i] = r.nextInt();
    }
    
    public void put(Object a, int raw_count)
    {
        int init_hash = a.hashCode();
        
        //to make this more compact, we store only the exponent of the value, 
        //to a specific base. 
        byte expo_count = (byte) Math.min(Math.ceil(Math.log(raw_count)/log_base), 255);
        
        for(int i = 0; i < hashSeeds.length; i++)
        {
            int h = hash6432shift( (((long) hashSeeds[i]) << 32) | init_hash);
            h = Integer.remainderUnsigned(h, counts.length);
            
            counts[h] = (byte) Math.max(Byte.toUnsignedInt(counts[h]), expo_count);
        }
        
        added++;
    }
    
    public int get(Object a)
    {
        int init_hash = a.hashCode();
        
        int min_expo = 257;
        for(int i = 0; i < hashSeeds.length; i++)
        {
            int h = hash6432shift( (((long) hashSeeds[i]) << 32) | init_hash);
            h = Integer.remainderUnsigned(h, counts.length);
            
            min_expo = Math.min(Byte.toUnsignedInt(counts[h]), min_expo);
        }
        
        if(min_expo == 0)
            return 0;
        else
            return (int) Math.pow(base, min_expo);
    }
    
    public double lowestNonZeroCount()
    {
        int min_expo = 257;
        
        for(byte i : counts)
        {
            int v = Byte.toUnsignedInt(i);
            if(v != 0)
                min_expo = Math.min(v, min_expo);
        }
        
        return (int) Math.pow(base, min_expo);
    }
    
    /**
     * 
     * @param key
     * @return 
     * @see https://gist.github.com/badboy/6267743
     */
    static public int hash6432shift(long key)
    {
      key = (~key) + (key << 18); // key = (key << 18) - key - 1;
      key = key ^ (key >>> 31);
      key = key * 21; // key = (key + (key << 2)) + (key << 4);
      key = key ^ (key >>> 11);
      key = key + (key << 6);
      key = key ^ (key >>> 22);
      return (int) key;
    }

    private void writeObject(ObjectOutputStream oos) throws IOException 
    {
        oos.defaultWriteObject();
        oos.writeInt(divisor);
        oos.writeInt(added);
        oos.writeDouble(base);
        oos.writeDouble(log_base);
        
        
        oos.writeInt(counts.length);
        for(int i = 0; i < counts.length; i++)
            oos.writeByte(counts[i]);
        
        oos.writeInt(hashSeeds.length);
        for(int i = 0; i < hashSeeds.length; i++)
            oos.writeInt(hashSeeds[i]);
    }
    
    private void readObject(ObjectInputStream ois) throws ClassNotFoundException, IOException 
    {
        ois.defaultReadObject();
        
        divisor = ois.readInt();
        added = ois.readInt();
        base = ois.readDouble();
        log_base = ois.readDouble();
        
        counts = new byte[ois.readInt()];
        for(int i = 0; i < counts.length; i++)
            counts[i] = ois.readByte();
        
        hashSeeds = new int[ois.readInt()];
        for(int i = 0; i < hashSeeds.length; i++)
            hashSeeds[i] = ois.readInt();
    }
}
