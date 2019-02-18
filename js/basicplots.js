width = 1000
height=500;
barWidth = 40;
barOffset = 1.25;
totalDNS = 0;
totalTCP = 0;
totalARP = 0;
totalICMP = 0;
totalTELNET = 0;

//load in the json on execution for cool stats/other things not related to d3
var data;
$(".main").css("display", "none");
$.getJSON("https://api.myjson.com/bins/6i2tm", function(json) {
    console.log("json has been loaded");
    data = json;
    console.log(data[1])
    

    //collect all the different packet types and their maximums.
    totalDNS = getMaxPacketType("DNS", data);

    totalTCP = getMaxPacketType("TCP", data);

    totalARP = getMaxPacketType("ARP", data);

    totalICMP = getMaxPacketType("ICMP", data);

    totalTELNET = getMaxPacketType("TELNET", data);

    bar = "bar";
    //plotly bars
    var plotdata = [
        {
            x: ['DNS', 'TCP', 'ARP', 'ICMP', 'TELNET'],
            y: [totalDNS, totalTCP, totalARP, totalICMP, totalTELNET],
            type: bar,
            name: 'Packet Types'
        }
    ];

    var plotdata2 = [
        {
            labels: ['DNS', 'TCP', 'ARP', 'ICMP', 'TELNET'],
            values: [totalDNS, totalTCP, totalARP, totalICMP, totalTELNET],
            type: "pie",
            name: 'Packet Types'
        }
    ];

    var layoutBar = {
        title: "Packets detected",
    }

    var layoutPie = {
        title: "Packets detected",
        height: 500,
        width: 500,
    }
    
    Plotly.newPlot('bar-chart', plotdata, layoutBar);

    //plotly pie

    Plotly.newPlot('pie-chart', plotdata2, layoutPie);


    $("#loading").css("display", "none");
    $(".main").css("display", "block");

    //get the maximum value of the malicious activity, and count it for a certain packet.

    

});

//switch up the counts incase we need them in the html;
function getCount(name) {
switch(name) {
    case "DNS":
        return totalDNS;
        
    case "ICMP":
        return totalICMP;
    default:
        return 0;
}
}




function getMaxPacketType(protocol, jsonData) {
    max = 0;
    for(i = 0; i < jsonData.length; i++) {
        if(jsonData[i].DataType == protocol) {
            max++;
        }
    }
    return max;
}

function getTotalIP(source, jsonData) {
    max = 0;

    for(i = 0; i < jsonData.length; i++) {
        if(jsonData[i].SourceDevice == source || jsonData[i].DestinationDevice == source) {
             max++;
        }
        return max;
    }
}

function getTotalActivityType(activity, jsonData) {

}