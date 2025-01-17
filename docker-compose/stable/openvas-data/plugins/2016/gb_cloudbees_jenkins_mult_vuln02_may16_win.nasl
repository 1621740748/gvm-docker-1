###############################################################################
# OpenVAS Vulnerability Test
#
# Jenkins Multiple Vulnerabilities (Feb 2016) - Windows
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:jenkins:jenkins";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807331");
  script_version("2021-03-26T13:22:13+0000");
  script_cve_id("CVE-2016-0788", "CVE-2016-0789", "CVE-2016-0790", "CVE-2016-0791",
                "CVE-2016-0792");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2021-03-26 13:22:13 +0000 (Fri, 26 Mar 2021)");
  script_tag(name:"creation_date", value:"2016-05-20 15:08:55 +0530 (Fri, 20 May 2016)");

  script_name("Jenkins Multiple Vulnerabilities (Feb 2016) - Windows");

  script_tag(name:"summary", value:"This host is installed with Jenkins and is prone to
  multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - The verification of user-provided API tokens with the expected value did
    not use a constant-time comparison algorithm, potentially allowing
    attackers to use statistical methods to determine valid API tokens using
    brute-force methods.

  - The verification of user-provided CSRF crumbs with the expected value did
    not use a constant-time comparison algorithm, potentially allowing attackers
    to use statistical methods to determine valid CSRF crumbs using brute-force
    methods.

  - The Jenkins has several API endpoints that allow low-privilege users to POST
    XML files that then get deserialized by Jenkins. Maliciously crafted XML
    files sent to these API endpoints could result in arbitrary code execution.

  - An HTTP response splitting vulnerability in the CLI command documentation
    allowed attackers to craft Jenkins URLs that serve malicious content.

  - The Jenkins remoting module allowed unauthenticated remote attackers to open
    a JRMP listener on the server hosting the Jenkins master process, which
    allowed arbitrary code execution.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to obtain sensitive information, bypass the protection mechanism,
  gain elevated privileges, bypass intended access restrictions and execute
  arbitrary code.");

  script_tag(name:"affected", value:"Jenkins main line 1.649 and prior, Jenkins LTS 1.642.1 and prior.");

  script_tag(name:"solution", value:"Jenkins main line users should update to 1.650,
  Jenkins LTS users should update to 1.642.2.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"https://jenkins.io/security/advisory/2016-02-24/");
  script_xref(name:"URL", value:"https://www.contrastsecurity.com/security-influencers/serialization-must-die-act-2-xstream");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_jenkins_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("jenkins/detected", "Host/runs_windows");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! infos = get_app_full( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];
proto = infos["proto"];

if( get_kb_item( "jenkins/" + port + "/is_lts" ) ) {
  if( version_is_less( version:version, test_version:"1.642.2" ) ) {
    vuln = TRUE;
    fix = "1.642.2";
  }
} else {
  if( version_is_less( version:version, test_version:"1.650" ) ) {
    vuln = TRUE;
    fix = "1.650";
  }
}

if( vuln ) {
  report = report_fixed_ver( installed_version:version, fixed_version:fix, install_path:location );
  security_message( port:port, data:report, proto:proto );
  exit( 0 );
}

exit( 99 );
