function showVulnsTable(scanResult){
	var vulns = scanResult.vulnsTable.data;	
	var table = jQuery('#vulnsTable').DataTable({             
		"autoWidth": false, 
		"language": {
    		"emptyTable": "No vulnerabilities found"
		 },
		 "dom": '<"vulns-table-top"l<"custom-filters">>rt<"vulns-table-bottom"ip><"clear">',
        "aaData": vulns,
        "aoColumns":[    
        	{
	            "className": 'details-control',
	            "orderable": false,
	            "data":      null,
	            "defaultContent": ''
	        },     
            { "mData": "qid", sDefaultContent :  '-', "width": "6%"},
            { "mData": "title", sDefaultContent :  '-', "width": "40%"},
            { "mData": "cve_id", sDefaultContent :  '-', "width": "15%"},
            { "mData": "severity", sDefaultContent :  '-', "width": "5%"},          
            { "mData": "category", sDefaultContent :  '-', "width": "17%"},
            { "mData": "pci_vuln", sDefaultContent :  '-', "width": "5%"},
            { "mData": "type", sDefaultContent :  '-', "width": "10%"},
            { "mData": "bugtraq_id", sDefaultContent :  '-', "width": "15%"},
            { "mData": "exploitability", sDefaultContent :  '-'},
            { "mData": "associated_malware", sDefaultContent :  '-'}
           
        ],
        'aoColumnDefs': [
            { "sTitle": "", "aTargets": [0],"width": "2%"},      
        	{ "sTitle": "QID", "aTargets": [1], "width": "6%", "className": "center"},
            { "sTitle": "Title", "aTargets": [2], "width": "40%", "className": "center" },    
            { "sTitle": "CVE ID", "aTargets": [3], "width": "15%", "className": "center",
                "render":  function (data, type, row ) 
                {
                	        if(data != undefined)
                	        {
                                 var dataArr = data.split(',');
            				    if(dataArr.length > 1){
            					    return dataArr[0] +' + <a href="#" class="more-cve-records">' + (dataArr.length - 1) +' more</a>';
            				    }else{
            					    return data;
            				    }

                	        }
                	       
            			}
            },
            { "sTitle": "Severity", "aTargets": [4], "width": "5%", "className": "center"},       
            { "sTitle": "Category", "aTargets": [5], "width": "17%", "className": "center"},
            { "sTitle": "PCI Vuln?", "aTargets": [6], "width": "5%", "className": "center"},
            { "sTitle": "Type", "aTargets": [7], "width": "10%", "className": "center"},            
            { "sTitle": "Bug Traq Id", "aTargets": [8], "width": "15%", "className": "center"},
            { "sTitle": "Exploitability", "aTargets": [9], visible:false},
            { "sTitle": "Associated_Malware", "aTargets": [10], visible:false}
        ]
    });
	
	 jQuery('#vulnsTable tbody').on('click', 'td.details-control', function () {
	        var tr = jQuery(this).closest('tr');
	        var row = table.row( tr );
	 
	        if ( row.child.isShown() ) {
	            // This row is already open - close it
	            row.child.hide();
	            tr.removeClass('shown');
	        }
	        else {
	            // Open this row
	            row.child( format(row.data()) ).show();
	            tr.addClass('shown');
	        }
	    });
	    
	    jQuery("#vulnsTable tbody").on("click", ".more-cve-records", function(e){
	    	var tr = jQuery(this).closest('tr');
	    	var row = table.row( tr );
	    	if ( row.child.isShown() ) {
	            // This row is already open - close it
	            row.child.hide();
	            tr.removeClass('shown');
	        }
	        else
	        {
	    	    row.child( format(row.data()) ).show();
	            tr.addClass('shown');
	        }
	        return false;
	    });
	    
	    
	    jQuery(".softwares-custom-filters").html(
	    	'<div class="sev-filter-div">' + 
	    	'<span class="filters-label">Show Only: </span>' + '</div>'+ 
	    	'<ul class="filters-list">' +
	    	'<li><input class="custom-filter-checkbox" type="checkbox" id="sw-patchable" value="sw-patchable">  <label for="sw-patchable" class="checkbox-title"> Patchable  </li>' +
	    	'</ul>' 
	    );
	    jQuery(".custom-filters").html(
	    	'<div class="sev-filter-div">' + 
	    	'<span class="filters-label">Show Only: </span>' + 
	    	'<span class="sev-filter-label" >Severity </span>' + 
	    	'<select class="severity-dropdown">' + 
	    	'<option value="">All</option>' +
	    	'<option value="5"> 5 </option>' +
	    	'<option value="4"> 4 </option>' +
	    	'<option value="3"> 3 </option>' +
	    	'<option value="2"> 2 </option>' +
	    	'<option value="1"> 1 </option>' +
	    	'</select>' +
	    	'<span class="sev-filter-label" >PCI Vuln </span>' +
	    	'<select class="pci-dropdown">' + 
	    	'<option value="">All</option>' +
	    	'<option value="yes"> Yes </option>' +
	    	'<option value="no"> No </option>' +
	    	'</select>' +
	    	'<span class="sev-filter-label" >Vuln Type </span>' +
	    	'<select class="type-dropdown">' + 
	    	'<option value="">All</option>' +
	    	'<option value="Confirmed"> Confirmed </option>' +
	    	'<option value="Potential"> Potential </option>' +
	    	'</select>' +
	    	'</div>'+
	    	'<ul class="filters-list">' +
    		'<li><input class="custom-filter-checkbox" type="checkbox" id="exploitable" value="exploitable"><label for="exploitable" class="checkbox-title" > Exploitable </li>' +
    		'<li><input class="custom-filter-checkbox" type="checkbox" id="malware" value="malware"> <label for="malware" class="checkbox-title" > Associated Malware </li>' +
    		'</ul>' +
    		'<button type="button" id="reset" >Reset Filters</button>'
	    );
	    
	    jQuery(".custom-filters-left").html(
	    	
	    );
	    
	    jQuery('.severity-dropdown').on('change', function(e){
	    	 var optionSelected = jQuery("option:selected", this);
			 var valueSelected = this.value;
			 table.columns(3).search( valueSelected ).draw();
	    });
	    
	    jQuery('.pci-dropdown').on('change', function(e){
	    	 var optionSelected = jQuery("option:selected", this);
			 var valueSelected = this.value;
			 table.columns(6).search( valueSelected ).draw();
	    });  
	    
	    jQuery('.type-dropdown').on('change', function(e){
	    	 var optionSelected = jQuery("option:selected", this);
			 var valueSelected = this.value;
			 table.columns(7).search( valueSelected ).draw();
	    });
	    
	    jQuery(".custom-filter-checkbox").on("change", function(e){
		switch(this.value){	
			case 'exploitable': 
						var value = (this.checked)? 'true' : '';
						table.columns(9).search( value ).draw();
						break;
			case 'malware': 
						var value = (this.checked)? 'true' : '';
						table.columns(10).search( value ).draw();
						break;
		}
	});
	
	$( "#reset" ).click(function() 
	{
  		$(".severity-dropdown").val('');
  		$(".pci-dropdown").val('');
  		$(".type-dropdown").val('');
  		$("#exploitable").prop("checked",false);
  		$("#malware").prop("checked",false);

  		table.search( '' ).columns().search( '' ).draw();
	});
}


function format ( d ) {
    
    var cvss_base;
    var cvss_temporal;
    var cvss3_base;
    var cvss3_temporal;
    var cve_id;
    var results;

    if(d.cvss_base == undefined || d.cvss_base == null)
    {
    	cvss_base = " -";
    }
    else
    {
    	cvss_base = d.cvss_base;
    }
    if(d.cvss_temporal == undefined || d.cvss_temporal == null)
    {
    	cvss_temporal = " -";
    }
    else
    {
    	cvss_temporal= d.cvss_temporal;
    }
     if(d.cvss3_base == undefined || d.cvss3_base == null)
    {
    	cvss3_base = " -";
    }
    else
    {
    	cvss3_base = d.cvss3_base;
    }
    if(d.cvss3_temporal == undefined || d.cvss3_temporal == null)
    {
    	cvss3_temporal = " -";
    }
    else
    {
    	cvss3_temporal = d.cvss3_temporal;
    }
    if(d.cve_id == undefined || d.cve_id == null)
    {
    	cve_id = " -";
    }
    else
    {
    	cve_id = d.cve_id;
    }
    if(d.results == undefined || d.results == null)
    {
    	results = " -";
    }
    else
    {
    	results = d.results;
    }




    return '<table cellpadding="5" cellspacing="0" border="0" style="padding-left:50px;">'+
	    '<tr>'+
	    	'<td>CVSS Base Score: ' + cvss_base + '</td>'+
	    	'<td>CVSS Temporal Score: '+ cvss_temporal +'</td>'+
	    '</tr>'+
	    '<tr>'+
	    	'<td>CVSS3 Base Score: ' + cvss3_base + '</td>'+
	    	'<td>CVSS3 Temporal Score: '+ cvss3_temporal +'</td>'+
	    '</tr>'+
	    '<tr>'+
            '<td>CVE Ids</td>'+
            '<td>'+cve_id+'</td>'+
        '</tr>'+
        '<tr>'+
            '<td>Result</td>'+
            '<td>'+results+'</td>'+
        '</tr>'+
    '</table>';
}

function drawBuildSummary(reportObject){
	jQuery('#build-status').text((reportObject == "PASSED")? "Success" : "Failed");
	
	if(reportObject === "FAILED"){
		jQuery('#build-status').css('color', 'red');
		jQuery('.status-image').addClass('failed');
		jQuery('.status-image').removeClass('success');
	}else{
		jQuery('#build-status').css('color', 'green');
		jQuery('.status-image').removeClass('failed');
		jQuery('.status-image').addClass('success');
	}
	
	/*jQuery("#image-tags").text("-");
	if(reportObject.imageSummary.hasOwnProperty("Tags") && reportObject.imageSummary.Tags){
		var tags = reportObject.imageSummary.Tags.filter(function (el) { return el != null;	});
		var tagsStr = tags.join(', ');
		jQuery("#image-tags").text(tagsStr);
	}
	
	var size = reportObject.imageSummary.size;
	var sizeStr = bytesToSize(parseInt(size));
	jQuery("#image-size").text(sizeStr);*/
}

function showEvaluationSummary(scanResult){
	var isEvaluationResult = scanResult.isEvaluationResult;
	if(isEvaluationResult === 1){
		var reportObject = scanResult.evaluationResult;
		if(reportObject.qids){
			if(reportObject.qids.configured){
				jQuery("#qid-found .image-scan-status").removeClass("not-configured").addClass(reportObject.qids.result ? "ok" : "fail");
				jQuery("#qid-found .image-scan-status .tooltip-text").html("<b>Configured:</b> "+reportObject.qids.configured + "<br /><b>Found: </b>"+ (reportObject.qids.found ? reportObject.qids.found : "0"));
			}
		}
		if(reportObject.cveIds){
			if(reportObject.cveIds.configured){
				jQuery("#cve-found .image-scan-status").removeClass("not-configured").addClass(reportObject.cveIds.result ? "ok" : "fail");
				jQuery("#cve-found .image-scan-status .tooltip-text").html("<b>Configured:</b> "+reportObject.cveIds.configured + "<br /><b>Found: </b>"+ (reportObject.cveIds.found ? reportObject.cveIds.found : "None"));
			}
		}
		if(reportObject.cvss_base){
			if(reportObject.cvss_base.configured){
				jQuery("#cvss-found .image-scan-status").removeClass("not-configured").addClass(reportObject.cvss_base.result ? "ok" : "fail");
				jQuery("#cvss-found .image-scan-status .tooltip-text").html("<b>Configured:</b> CVSSv2 more than or equal to ("+reportObject.cvss_base.configured + ")<br /><b>Found: </b>"+ (reportObject.cvss_base.found ? reportObject.cvss_base.found : "None"));
			}
		}
		if(reportObject.cvss3_base){
			if(reportObject.cvss3_base.configured){
				jQuery("#cvss-found .image-scan-status").removeClass("not-configured").addClass(reportObject.cvss3_base.result ? "ok" : "fail");
				jQuery("#cvss-found .image-scan-status .tooltip-text").html("<b>Configured:</b> CVSSv3 more than or equal to ("+reportObject.cvss3_base.configured + ")<br /><b>Found: </b>"+ (reportObject.cvss3_base.found ? reportObject.cvss3_base.found : "None"));
			}
		}
		if(reportObject.pci_vuln){
			if(reportObject.pci_vuln.configured){
				jQuery("#pci-found .image-scan-status").removeClass("not-configured").addClass(reportObject.pci_vuln.result ? "ok" : "fail");
				jQuery("#pci-found .image-scan-status .tooltip-text").html("<b>Configured:</b> more than or equal to 1<br /><b>Found: </b>"+ (reportObject.pci_vuln.found ? reportObject.pci_vuln.found : "None"));
			}
		}
		if(reportObject.severities){
			var severityObj = reportObject["severities"];
			for(var i=1; i<=5; i++){
				if(severityObj[i])
					if(!(severityObj[i].configured === null || severityObj[i].configured === -1)){
						jQuery("#sev" + i + "-found .image-scan-status").removeClass("not-configured").addClass(severityObj[i].result ? "ok" : "fail");
						jQuery("#sev" + i + "-found .image-scan-status .tooltip-text").html("<b>Configured:</b> more than or equal to "+severityObj[i].configured + "<br /><b>Found: </b>"+ (severityObj[i].found !== null ? severityObj[i].found : "0"));
					}
			}
		}
		if(reportObject.qids.excluded || reportObject.cveIds.excluded)
			jQuery("#excluded-items").html(reportObject.qids.excluded ? "<b>*Excluded QIDs: </b>" + reportObject.qids.excluded : "<b>*Excluded CVEs: </b>"+ reportObject.cveIds.excluded);
		if(reportObject.potentialVulnsChecked)
			jQuery("#potential-checked").html("<i><b>*</b>Considered potential vulnerabilities.</i>");
	}	
}

function drawCVulnsCharts(scanResults) {

    var show_tooltip = true;
    var count = Array();
    var severity = Array();
   	var colors = ["#E8E4AE", "#F4BB48", "#FAA23B", "#DE672A", "#D61E1C"];
    var c = jQuery("#sevCVulns").get(0);
    var ctx = c.getContext("2d");

    jQuery("#sevCVulns-error").hide();
    jQuery("#sevCVulns").show();
    jQuery("#pie-legend-div-c").show();

    if (scanResults.vulns == "0") {
        jQuery("#sevCVulns").hide();
        jQuery("#pie-legend-div-c").hide();
        jQuery("#sevCVulns-error").show();
    } else {
     	var d = scanResults.cVulnsBySev;
        var i = 0;
        var total = 0;

        for (var key in d) {
            count[i] = d[key];
            severity[i] = key;
            total += count[i];
            i++;
        }

        var labels = count;
        
        if (!count.some(el => el !== 0)) {
            count = ["1", "1", "1", "1", "1"];
            severity = ["1", "2", "3", "4", "5"];
            labels = ["0", "0", "0", "0", "0"];
            colors = ["#B0BFc6", "#B0BFc6", "#B0BFc6", "#B0BFc6", "#B0BFc6"];
            show_tooltip = false;
        }

        var options = {
            responsive: true,
            plugins: {
                legend: {
                    display: true,
                    position: 'right'
                },
                tooltip: {
                    enabled: show_tooltip,
                    callbacks: {
                        label: function(context) {
                            var label = context.label;
                            return label;

                        }
                    }
                }
            }
        };

        var pieData = {
            "datasets": [{

                "data": count,
                "backgroundColor": colors
            }],

            // These labels appear in the legend and in the tooltips when hovering different arcs
            "labels": [
                "Sev " + severity[0].toString() + " : " + labels[0],
                "Sev " + severity[1].toString() + " : " + labels[1],
                "Sev " + severity[2].toString() + " : " + labels[2],
                "Sev " + severity[3].toString() + " : " + labels[3],
                "Sev " + severity[4].toString() + " : " + labels[4]
            ]

        };

        jQuery("#confTotCount").text(total);

       new Chart(ctx, {
            "type": "doughnut",
            "data": pieData,
            "options": options
        });
    }
}

function drawPVulnsCharts(scanResults){
	
    var show_tooltip = true;
    var count = Array();
    var severity = Array();
    var colors = ["#E8E4AE", "#F4BB48", "#FAA23B", "#DE672A", "#D61E1C"];
    var c = jQuery("#sevPVulns").get(0);
    var ctx = c.getContext("2d");

    jQuery("#sevPVulns-error").hide();
    jQuery("#sevPVulns").show();
    jQuery("#pie-legend-div-p").show();

    if (scanResults.vulns == "0") {
        jQuery("#sevCVulns").hide();
        jQuery("#pie-legend-div-p").hide();
        jQuery("#sevCVulns-error").show();
    } else {
        var d = scanResults.pVulnsBySev;
        var i = 0;
        var total = 0;

        for (var key in d) {
            count[i] = d[key];
            severity[i] = key;
            total += count[i];
            i++;
        }

        var labels = count;
        
        if (!count.some(el => el !== 0)) {
            count = ["1", "1", "1", "1", "1"];
            severity = ["1", "2", "3", "4", "5"];
            labels = ["0", "0", "0", "0", "0"];
            colors = ["#B0BFc6", "#B0BFc6", "#B0BFc6", "#B0BFc6", "#B0BFc6"];
            show_tooltip = false;
        }

        var options = {
            responsive: true,
            plugins: {
                legend: {
                    display: true,
                    position: 'right'
                },
                tooltip: {
                    enabled: show_tooltip,
                    callbacks: {
                        label: function(context) {
                            var label = context.label;
                            return label;

                        }
                    }
                }
            }
        };

        var pieData = {
            "datasets": [{

                "data": count,
                "backgroundColor": colors
            }],

            // These labels appear in the legend and in the tooltips when hovering different arcs
            "labels": [
                "Sev " + severity[0].toString() + " : " + labels[0],
                "Sev " + severity[1].toString() + " : " + labels[1],
                "Sev " + severity[2].toString() + " : " + labels[2],
                "Sev " + severity[3].toString() + " : " + labels[3],
                "Sev " + severity[4].toString() + " : " + labels[4]
            ]

        };

        jQuery("#confTotCount").text(total);

       new Chart(ctx, {
            "type": "doughnut",
            "data": pieData,
            "options": options
        });
    }
}