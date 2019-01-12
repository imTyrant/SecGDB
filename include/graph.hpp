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
};

struct Edge
{
    Vertex &src;
    Vertex &dest;
    size_t weight;
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

class Graph
{
  public:
    std::unordered_map<std::string, Vertex> vertices;
    std::unordered_map<Vertex, std::list<Edge>, std::hash<Vertex>> adjacency_list;

    size_t num_vertices;
    size_t num_edges;

    Graph();

    void build_graph(const std::string &file_path);
};

#endif