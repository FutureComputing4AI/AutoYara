# AutoYara

This is the java code implementing the AutoYara algorithm, from out paper [_Automatic Yara Rule Generation Using Biclustering_](https://arxiv.org/abs/2009.03779). Given a set up input files that belong to a given malware family, AutoYara can create [Yara](https://yara.readthedocs.io/en/stable/) rules from the input samples. Our testing indicates it can be successful  with as few as 2 samples files, and can achieve very low false positive rates. The goal is to help analysts that need to create rules to weed out the easy families first, so that they can work on the samples that do not yield to automation. 

This is research code, and comes with no warranty or support. 


## Quick Start

You can download a pre-built binary of Autoyara from the release tab. If you have Java 11 (or greater) installed, you can get started by using the `-i` flag and providing a path to a file. If you give a folder, files will be selected from that folder recursively.  Multiple files/paths can be specified using multiple `-i` arguments. 

```
java -jar AutoYara.jar -i ~/family_dataset/test/azero/
```

The final output will be written to the current directory. If you want to change the output directory or output file name, you can use  `--out /path/to/name.yara` to change that.  

Unless you run on a few hundred files or more, the results should be done in a minute or two. The output is a standard Yara rule, like the below truncated example. 
```
rule test
{
    //Input TP Rate:
    //170/184
    strings:
        //Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.375 Found in 24 files
        $x705 = { 6C 00 65 00 20 00 6E 00 6F 00 74 00 20 00 66 00 } //This might be a string? Looks like:le not f
        //Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 14 files
        $x706 = { 44 24 04 59 5A 5E 5B C3 8D 40 00 55 8B EC 51 53 } //This might be a string? Looks like:D$YZ^[@UQS
        //Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.9237949406953985 Found in 20 files
        $x1 = { 83 C4 10 C2 08 00 CC CC CC CC CC CC CC CC CC CC } 
        //Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 28 files
        $x708 = "`3d3h3l3p3t3x3|3" ascii
        //Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.875 Found in 13 files
        $x709 = { 5B 8B E5 5D C3 90 55 8B EC 83 C4 F0 53 56 57 89 } //This might be a string? Looks like:[]USVW
        //Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.202819531114783 Found in 14 files
        $x711 = { 00 00 00 46 69 6C 65 54 69 6D 65 54 6F 4C 6F 63 } //This might be a string? Looks like:FileTimeToLoc
        //Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.75 Found in 39 files
        $x5 = { 6D 3A 61 73 6D 2E 76 33 22 3E 3C 73 65 63 75 72 } //This might be a string? Looks like:m:asm.v3"><secur
        //Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.577819531114783 Found in 105 files
        $x8 = "etLastActivePopu" ascii
    condition:
    (705 of ($x0,$x1,$x2,$x3,$x4, /*this goes on for a while*/ ) ) or 
    (650 of (/*you get the idea..*/)
```

The comment `//170/184` indicates this rule was built from 184 sample files, and successfully fires on 170 of the original files. Rules may contain any number of conditions that use a sub-set of rules. When the bytes used in a rule are all ASCII strings, the output will be re-written as an `ascii` type signature component. When rules look like strings but are not all valid printable characters, you will see the `This might be a string?` comment that attempts to show the printabel portion of a string. 

The `Bening` and `Malicious` `FP est` components of every rule are based on the counting bloom filters. Negative zero indicates that the n-gram was not contained in the bloom filters at all. You can use these non-zero estimates as a guide to manually modifying the rule if a bad component was selected. This, combined with increasing/decreasing the number of rules needed for each condition can be used to manually fine-tune the FP/TP behavior of generated rules. This is what we did in the paper to produce Table 3. The `Entropy` line indicates the byte entropy of the given rule, and can also be useful for adjusting to reduce FP (remove low entropy) or increase TP (remove high entropy), as well as getting a quick idea about what type of content a rule component might be from (e.g., code has an average entropy ~5.0, plain text ~4.3). 

You can find more information about other command line options using the `--help` flag. 

## Citations

If you use the AutoYara algorithm or code, please cite our work! 

```
@inproceedings{Raff2020autoyara,
author = {Raff, Edward and Zak, Richard and Munoz, Gary Lopez and Fleming, William and Anderson, Hyrum S. and Filar, Bobby and Nicholas, Charles and Holt, James},
booktitle = {13th ACM Workshop on Artificial Intelligence and Security (AISec'20)},
doi = {10.1145/3411508.3421372},
title = {{Automatic Yara Rule Generation Using Biclustering}},
url = {http://arxiv.org/abs/2009.03779},
year = {2020}
}

```

## Contact 

If you have questions, please contact 

Jim Holt <holt@lps.umd.edu>
Edward Raff <edraff@lps.umd.edu>
Richard Zak <rzak@lps.umd.edu>
