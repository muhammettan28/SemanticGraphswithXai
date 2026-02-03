#!/usr/bin/env python3
"""
Graf metriklerini hesaplayan modül.
Centrality, clustering, path length gibi yapısal özellikleri çıkarır.
"""

import networkx as nx
import numpy as np


def compute_graph_metrics(G: nx.DiGraph) -> dict:
    """
    NetworkX DiGraph'tan yapısal metrikleri hesaplar.
    
    Returns:
        dict: Graf metrikleri
            - node_count: Node sayısı
            - edge_count: Edge sayısı  
            - density: Graf yoğunluğu
            - avg_betweenness: Ortalama betweenness centrality
            - avg_clustering: Clustering coefficient
            - pagerank_max: Maksimum PageRank değeri
            - avg_in_degree: Ortalama gelen derece
            - avg_out_degree: Ortalama giden derece
    """
    
    metrics = {}
    
    N = G.number_of_nodes()
    E = G.number_of_edges()
    
    metrics['node_count'] = N
    metrics['edge_count'] = E
    
    # Boş graf kontrolü
    if N == 0:
        return {
            'node_count': 0,
            'edge_count': 0,
            'density': 0.0,
            'avg_betweenness': 0.0,
            'avg_clustering': 0.0,
            'pagerank_max': 0.0,
            'avg_in_degree': 0.0,
            'avg_out_degree': 0.0
        }
    
    # Density
    metrics['density'] = nx.density(G)
    
    # Betweenness Centrality (ağırlıklı)
    try:
        betweenness = nx.betweenness_centrality(G, weight='weight')
        metrics['avg_betweenness'] = np.mean(list(betweenness.values()))
    except:
        metrics['avg_betweenness'] = 0.0
    
    # Clustering Coefficient (undirected versiyonu kullan)
    try:
        G_undirected = G.to_undirected()
        clustering = nx.clustering(G_undirected, weight='weight')
        metrics['avg_clustering'] = np.mean(list(clustering.values()))
    except:
        metrics['avg_clustering'] = 0.0
    
    # PageRank (use undirected for better convergence)
    try:
        G_undirected = G.to_undirected()
        pagerank = nx.pagerank(G_undirected, weight='weight', max_iter=100, tol=1e-6)
        metrics['pagerank_max'] = max(pagerank.values())
    except:
        # Fallback to uniform distribution
        metrics['pagerank_max'] = 1.0 / N if N > 0 else 0.0
    
    # Degree stats
    in_degrees = [d for _, d in G.in_degree()]
    out_degrees = [d for _, d in G.out_degree()]
    
    metrics['avg_in_degree'] = np.mean(in_degrees) if in_degrees else 0.0
    metrics['avg_out_degree'] = np.mean(out_degrees) if out_degrees else 0.0
    
    return metrics
