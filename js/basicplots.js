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
        height: 600,
        width: 600,
    }
    
    //plot the bar
    Plotly.newPlot('bar-chart', plotdata, layoutBar);

    //plotly pie
    Plotly.newPlot('pie-chart-packets', plotdata2, layoutPie);

    //malicious packets

    //get the maximum value of the malicious activity, and count it for a certain packet.

    //get the maximum of each.

    maxMalicious = getTotalActivityType("mirai", data);
    maxNormal = getTotalActivityType("norm", data);
    maxDNS = getTotalActivityType("dns", data);
    
    var packets = getMaliciousIPS(data);

    //create a new pie chart with the new malicious packets.

    var packetsLabels = [];
    var packetsValues = [];
    packets.sort();

    packets.forEach(function(packet) {
        packetsLabels.push(packet.address);
        packetsValues.push(packet.maliciousPackets);
    });

    //plot data for the malicious IP chart

    var plotDataIPs = [
        {
        labels: packetsLabels,
        values: packetsValues,
        type: "pie",
        name: "Ip addresses that sent malicious packets",
        }
    
    ]

    var layoutPieIP = {
        title: "Ip addresses that sent malicious packets",
        height: 600,
        width: 600,
    }

    // create plot data for total packets.

    var layoutPieMalPackets =
        {
            title: "Packets that were consider to be malicious, normal or DNS",
            height: 600,
            width: 600,
        }

        var plotDataMalPackets = [
            {
            labels: ["Malicious", "Normal", "DNS"],
            values: [maxMalicious, maxNormal, maxDNS],
            type: "pie",
            name: "Ip addresses that sent malicious packets",
            }
        
        ]
    

    Plotly.newPlot('pie-chart-IPs', plotDataIPs, layoutPieIP);
    Plotly.newPlot('pie-chart-MalPacks', plotDataMalPackets, layoutPieMalPackets);



    //always leave this at the bottom!
    $("#loading").css("display", "none");
    $(".main").css("display", "block");

});

//switch up the counts incase we need them in the html;
function getCount(name) {
switch(name) {
    case "DNS":
        return totalDNS;
    case "ICMP":
        return totalICMP;
    case "ARP":
        return totalARP;
    case "TELNET":
        return totalTELNET;
    case "TCP":
        return totalTCP;
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
    max = 0;

    for(i = 0; i < jsonData.length; i++) {
        if(jsonData[i].Activity == activity) {
            max++
        }
    }
    return max;
}

//this function loops through and gets all specfied packets that were considered malicious 


function getMaliciousIPS(jsonData) {
    // loop through object and get all IPS that are sending packets that are malicious
    //use a dictionary of sorts
    // key : ip (string) value : total malicious strings (number)

    var IPdict = {};
    var Packets = [];

    for(i = 0; i < jsonData.length; i++) {
        // has the address appeared already?
        found = false;
        for(j = 0; j < Packets.length; j++) {
        
            if(jsonData[i].SourceDevice == Packets[j].address) {
                found = true;

               if(jsonData[i].Activity == "mirai") {

                    Packets[j].maliciousPackets++;

                }
                
            }
        }

        //if it hasn't, then add it
        if(found == false) {

            var packet = {}

            packet.address = jsonData[i].SourceDevice;

            if(jsonData.Activity = "mirai") {
                packet.maliciousPackets = 1;
                Packets.push(packet);
            }
            
        }
        
    }
    return Packets;
}