/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package edu.lps.acs.ml.autoyara;


import java.util.List;
import jsat.DataSet;
import jsat.SimpleDataSet;
import jsat.classifiers.CategoricalData;
import jsat.classifiers.DataPoint;
import jsat.clustering.VBGMM;
import jsat.clustering.biclustering.Bicluster;
import jsat.clustering.biclustering.SpectralCoClustering;
import jsat.linear.DenseVector;
import jsat.linear.Matrix;
import jsat.linear.SubMatrix;
import jsat.linear.TruncatedSVD;
import jsat.utils.IntList;

public class SpectralCoClusteringVBMM implements Bicluster
{
    public static SpectralCoClustering.InputNormalization DEFAULT = SpectralCoClustering.InputNormalization.BISTOCHASTIZATION;

    public SpectralCoClustering.InputNormalization inputNormalization = SpectralCoClustering.InputNormalization.BISTOCHASTIZATION;
    
    @Override
    public void bicluster(DataSet dataSet, int clusters, boolean parallel, List<List<Integer>> row_assignments, List<List<Integer>> col_assignments) 
    {
        
        //﻿1. Given A, form An = D_1^{−1/2} A D_2^{−1/2}
        Matrix A = dataSet.getDataMatrix();
                        
        DenseVector R = new DenseVector(A.rows());
        DenseVector C = new DenseVector(A.cols());
        
        Matrix A_n = inputNormalization.normalize(A, R, C);
        
        
        //﻿2. Compute l = ceil(log2 k) singular vectors of A_n, u2, . . . u_l+1 and v2, . . . v_l+1, and form the matrix Z as in (12)
        int l = (int) Math.ceil(Math.log(clusters)/Math.log(2.0));
        
        
        //A_n has r rows and c columns. We are going to make a new data matrix Z
        //Z will have (r+c) rows, and l columns. 
        SimpleDataSet Z = create_Z_dataset(A_n, l, R, C, inputNormalization);//+1 b/c we are going to skip the first SV
        
        VBGMM vbgmm = new VBGMM(VBGMM.COV_FIT_TYPE.DIAG);

        int[] joint_designations = vbgmm.cluster(Z, parallel, null);
        
        createAssignments(Z, row_assignments, col_assignments, clusters, A, joint_designations, vbgmm);
        
    }

    public void bicluster(DataSet dataSet, boolean parallel, List<List<Integer>> row_assignments, List<List<Integer>> col_assignments)
    {
        SpectralCoClustering.InputNormalization inputNormalization ;
        inputNormalization = DEFAULT;
            
        //﻿1. Given A, form An = D_1^{−1/2} A D_2^{−1/2}
        Matrix A = dataSet.getDataMatrix();
                        
        DenseVector R = new DenseVector(A.rows());
        DenseVector C = new DenseVector(A.cols());
        
        Matrix A_n = inputNormalization.normalize(A, R, C);
        
        //﻿2. Compute l = ceil(log2 k) singular vectors of A_n, u2, . . . u_l+1 and v2, . . . v_l+1, and form the matrix Z as in (12)
        int k_max = Math.min(A.rows(), A.cols());
        int l = (int) Math.ceil(Math.log(k_max)/Math.log(2.0));
        
        
        SimpleDataSet Z = create_Z_dataset(A_n, l, R, C, inputNormalization);
        
        VBGMM vbgmm = new VBGMM(VBGMM.COV_FIT_TYPE.DIAG);
        int[] joint_designations = vbgmm.cluster(Z, parallel, null);
        int clusters = 0;
        for(int i : joint_designations)
            clusters = Math.max(clusters, i);
        clusters++;
        
        createAssignments(Z, row_assignments, col_assignments, clusters, A, joint_designations, vbgmm);
    }

    private SimpleDataSet create_Z_dataset(Matrix A_n, int l, DenseVector R, DenseVector C, SpectralCoClustering.InputNormalization inputNormalization) 
    {
        //A_n has r rows and c columns. We are going to make a new data matrix Z
        //Z will have (r+c) rows, and l columns.
        TruncatedSVD svd = new TruncatedSVD(A_n, l+1);//+1 b/c we are going to skip the first SV
        Matrix U = svd.getU();
        Matrix V = svd.getV().transpose();
        //In some cases, Drop the first column, which corresponds to the first SV we don't want
        int to_skip = 1;
        U = new SubMatrix(U, 0, to_skip, U.rows(), l+to_skip);
        V = new SubMatrix(V, 0, to_skip, V.rows(), l+to_skip);
        /* Orig paper says to do this multiplication for re-scaling. Why not for
         * bistochastic? Its very similar! b/c in "﻿Spectral Biclustering of 
         * Microarray Data: Coclustering Genes and Conditions" where bistochastic
         * is introduced, on page 710: "﻿Once D1 and D2 are found, we ﻿apply SVD to 
         * B with no further normalization "
         * 
         */
        if(inputNormalization == SpectralCoClustering.InputNormalization.SCALE)
        {
            Matrix.diagMult(R, U);
            Matrix.diagMult(C, V);
        }
        
        SimpleDataSet Z = new SimpleDataSet(l, new CategoricalData[0]);
        for(int i = 0; i < U.rows(); i++)
            Z.add(new DataPoint(U.getRow(i)));
        for(int i = 0; i < V.rows(); i++)
            Z.add(new DataPoint(V.getRow(i)));
        return Z;
    }
    
    private void createAssignments(SimpleDataSet Z, List<List<Integer>> row_assignments, List<List<Integer>> col_assignments, int clusters, Matrix A, int[] joint_designations, VBGMM vbgmm) 
    {
        clusters = vbgmm.mixtureAssignments(Z.getDataPoint(0).getNumericalValues()).length;
        //prep label outputs
        row_assignments.clear();
        col_assignments.clear();
        for(int c = 0; c < clusters; c++)
        {
            row_assignments.add(new IntList());
            col_assignments.add(new IntList());
        }
        
        int n = A.rows();
        double thresh = 1.0/(row_assignments.size()+1);
        for(int z = 0; z < Z.size(); z++)
        {
            double[] assignments = vbgmm.mixtureAssignments(Z.getDataPoint(z).getNumericalValues());

            int assigned = 0;
            for(int k = 0; k < assignments.length; k++)
            {
                if(assignments[k] < thresh)
                    continue;//not happening
                assigned++;
                if(z < A.rows())//maybe add this row
                {
                    row_assignments.get(k).add(z);
                }
                else//maybe add this column
                {
                    col_assignments.get(k).add(z-A.rows());
                }
            }

        }
        
        //Now we need to prune potential false bi-clusterings that have only features or only rows
        for(int j = row_assignments.size()-1; j >= 0; j--)
        {
            if(row_assignments.get(j).isEmpty() || col_assignments.get(j).isEmpty())
            {
                row_assignments.remove(j);
                col_assignments.remove(j);
            }
        }
    }

    @Override
    public SpectralCoClusteringVBMM clone() 
    {
        return this;
    }
    
}