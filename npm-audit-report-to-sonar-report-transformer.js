const fs = require('fs');
const _ = require('lodash')

if (process.argv.length === 2) {
  console.error('     Expected at least one argument!');
  process.exit(1);
}

const sourceJsonPath= (process.argv[2]);

console.log("     Loading file " + sourceJsonPath + " .... ");
var data = require(sourceJsonPath);
console.log("     ....File Loaded");

function getSonarSeverity(sever) {
        switch(sever.toUpperCase()) {
          case 'CRITICAL':
            sever = "CRITICAL";
            break;
          case 'HIGH':
            sever = "MAJOR";
            break;
          case 'MODERATE':
            sever = "MINOR";
            break;
          case 'LOW':
            sever = "INFO";
            break;
          case 'INFO':
            sever = "INFO";
            break;
          default:
            sever = "INFO";
        }
        return sever;
}

function getModules(vulnerabilities) { 
        var output = [];

        _.forEach(vulnerabilities, (vulnerability) => {
          var module = {};
          module.module = vulnerability.name;
	  vulnerability.severity = getSonarSeverity(vulnerability.severity);
          module.issues = getIssues(vulnerability.via,vulnerability);

          output.push(module);
        });
	return output;
}

function getIssues(vias, context) {
    var output = [];

	var fixAvailable = "<Not defined>";
	if(context.fixAvailable.hasOwnProperty("name")){
		fixAvailable = context.fixAvailable.name + " (" + context.fixAvailable.version + ")";
	}else{
		fixAvailable = context.name +  " (Upper version to " + context.range + ")";
		if(context.range == "*")
		   fixAvailable = context.fixAvailable;
	}

    var viasToProcess = [];
    if(context.isDirect){
		// Full Definition Direct Vulnerability
		viasToProcess = vias.slice(0,1);
	}else{
		  if(vias[0].hasOwnProperty("range")){
			  // Full Definition No Direct Vulnerability
              viasToProcess = vias.slice();
		  }else{
			  // Short Definition No Direct Vulnerability
      		  viasToProcess = vias.slice(0,1);
		  }
	}

	viasToProcess.forEach(function(via){
	  //console.log(via);
	  var messageLocation = " | Direct Vulnerability : ".concat(context.isDirect);

	  if(context.isDirect){
	      // Full Definition Direct Vulnerability
		  messageLocation = messageLocation.concat(" | Vulnerable : ".concat(context.range));
		  messageLocation = messageLocation.concat(" | Fix Available : ".concat(fixAvailable));
	  }
	  else {
		  if(via.hasOwnProperty("range")){
		    // Full Definition No Direct Vulnerability
		    messageLocation = messageLocation.concat(" | Vulnerable : ".concat(via.range));
   		    messageLocation = messageLocation.concat(" | Fix Available : ".concat(fixAvailable));
		    if(via.hasOwnProperty("cvss")){
	   		    messageLocation = messageLocation.concat(" | Score : ".concat(via.cvss.score));
		    }
		    if(via.hasOwnProperty("cwe")){
			    var cwes = via.cwe.join(',');
	   		    messageLocation = messageLocation.concat(" | Category : ".concat(cwes));
		    }
   		    messageLocation = messageLocation.concat(" | ".concat(via.title));
			if(via.hasOwnProperty("url")){
   		        messageLocation = messageLocation.concat(" (See ".concat(via.url).concat(")"));
			}
		  } else {
		    // Short Definition No Direct Vulnerability
		    messageLocation = messageLocation.concat(" | Vulnerable : ".concat(context.range));
   		    messageLocation = messageLocation.concat(" | Fix Available : ".concat(fixAvailable));
		  }
	  } //end if(context.isDirect){

	  var issue = {};

	  issue.engineId = "NPMAudit";
	  issue.type = "VULNERABILITY";
	  issue.ruleId = "UsingComponentWithKnownVulnerability";
	  issue.severity = context.severity;

	  // Issue Primary Location
	  var messageLocationWithModule = "Module : ".concat(context.name);
	  var textRangePrimLocation = { "startLine": 13 };
	  var location = { "message": messageLocationWithModule.concat(messageLocation) , "filePath": "package.json", "textRange": textRangePrimLocation};
	  //console.log("    Primary location: " + location.message);

	  issue.primaryLocation = location;
	  
	  // Issue Secondary Location
	  //if(context.nodes.length > 1){
		//var secondaryLocations = [];
     	//        context.nodes.splice(1).forEach(function(node){
		//  var messageSecLocationWithModule = "Module : ".concat(node);
		//  var textRangeSecLocation = { "startLine": 13 };
		//  var secLocation = { "message": messageSecLocationWithModule.concat(messageLocation) , "filePath": "package.json", "textRange": textRangeSecLocation };
		  //console.log("    Secondary location: " + secLocation.message);
		//  secondaryLocations.push(secLocation);
		//});

		//issue.secondaryLocations = secondaryLocations;
	  //}

	  //console.log(issue);
		
      output.push(issue);

    });

    return output;
}

var my_modules = getModules(data.vulnerabilities);
//console.log(my_modules);

var result = {};
var issues = [];

my_modules.forEach(function(module){
  issues = issues.concat(module.issues);
});

result.issues = issues;

//console.log(result);

console.log("     Total Vulnerabilities: " + result.issues.length);

const targetJsonPath = sourceJsonPath + ".transf";

const jsonString = JSON.stringify(result, null, 2);

fs.writeFile(targetJsonPath, jsonString, err => {
  if (err) {
    console.error(err);
  } else {
    // file written successfully
    console.log("     "+ targetJsonPath + " saved ");
  }
});
