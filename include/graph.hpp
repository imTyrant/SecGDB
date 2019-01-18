#ifndef SEC_GDB_H_GRAPH
#define SEC_GDB_H_GRAPH

#include <iostream>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <list>

struct Vertex
{
    std::string name;
    size_t in_degree;
    size_t out_degree;

    inline bool operator==(const Vertex &v) const
    {
        return name == v.name;
    }
};

template<class T>
struct Edge
{
    Vertex &src;
    Vertex &dest;
    T weight;

    inline bool operator==(const Edge &e) const
    {
        if (src == e.src && dest == e.dest) return true;
        return false;
    }
};

namespace std
{
    template <>
    struct hash<Vertex>
    {
        size_t operator()(const Vertex &v) const
        {
            return std::hash<string>()(v.name);
        }
    };

    template <>
    struct equal_to<Vertex>
    {
        bool operator()(const Vertex &x, const Vertex &y) const
        {
            return x.name == y.name;
        }
    };
} // namespace std

template<class T>
class Graph
{
  public:
    // typedef typename std::list<Edge<T>>::iterator iterator;

    std::unordered_map<std::string, Vertex> vertices;
    std::unordered_map<Vertex, std::list<Edge<T>>, std::hash<Vertex>> adjacency_list;

    size_t num_vertices;
    size_t num_edges;

    Graph();

    typename std::list<Edge<T>>::iterator find_edge(const Vertex &src, const Vertex &dest);

    void add_edge(std::string &src, std::string &dest, T &weight);

    void modify_edge(std::string &src, std::string &dest, T &weight);

    void clear();
};

void build_graph(Graph<size_t> &graph, const std::string &file_path);

#endif