var data = [30, 20, 10, 40];
d3.select(".chart") 
    .selectAll("div")
    .data(data)
        .enter()
        .append("div")
        .style("height", function(d) { return d + "px"; })
        .style("width", 20 + "px")
        .text(function(d) { return d; });
        
