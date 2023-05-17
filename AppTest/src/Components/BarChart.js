import { useD3 } from '../hooks/useD3';
import React from 'react';
import * as d3 from 'd3';

function BarChart({ data}) {
  const ref = useD3(
    (svg) => {
      const box = document.querySelector(".result");
      const width = box.offsetWidth;
      const height = box.offsetHeight;
      
      
      const xScale = d3.scaleLinear()
            .domain([0, d3.max(data,d=>d[1])])
    			 .range([0, width*0.55]);
      const yScale = d3.scaleLinear()
            .domain([0, data.length])
            .range([0, height*0.95]);
      const w = width*0.05;    
      
      
      svg.selectAll("rect")
        .data(data)
        .enter()
        .append("rect")
        .attr("rx",15)
        .attr("y", (d, i) => yScale(i)+ (yScale(2) - yScale(1))/2 - (yScale(2) - yScale(1))/4)
        .attr("x", (d, i) => w)
        .attr("width", (d, i) => xScale(d[1]))
        .attr("height", (yScale(2) - yScale(1))/2)
        .attr("fill", "navy")
        .attr("class", "bar")
        .append("title")
        .text((d) => d);
        
    
      svg.selectAll('text.rotation')
      .data(data)
      .enter()
      .append('text')
      .text((d)=> d[0] +" - "+ parseInt(d[1]*100) +"%")
      .classed('rotation', true)
      .attr('fill', 'black')
      .attr('transform', (d,i)=>{
        return 'translate( '+ (xScale(d[1])+ w + width*0.01) +' , '+ (yScale(i)+ (yScale(2) - yScale(1))/2 + (yScale(2) - yScale(1))/6) +')';
      })
      .style("font-size",width*0.04);
      

      
    },
    [data]
  );

  return (
    <svg
      ref={ref}
      style={{
        height: "100%",
        width: "100%",
        marginRight: "auto",
        marginLeft: "auto",
        textAlign: "center"
      }}
    >
      <g className="plot-area" />
      <g className="x-axis" />
      <g className="y-axis" />
    </svg>
  );
}

export default BarChart;