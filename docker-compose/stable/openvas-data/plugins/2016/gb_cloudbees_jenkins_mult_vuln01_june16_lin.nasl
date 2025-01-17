###############################################################################
# OpenVAS Vulnerability Test
#
# Jenkins Multiple Vulnerabilities (Feb 2015) - Linux
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
  script_oid("1.3.6.1.4.1.25623.1.0.807341");
  script_version("2021-03-26T13:22:13+0000");
  script_cve_id("CVE-2015-1806", "CVE-2015-1807", "CVE-2015-1808", "CVE-2015-18010");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2021-03-26 13:22:13 +0000 (Fri, 26 Mar 2021)");
  script_tag(name:"creation_date", value:"2016-06-22 14:01:42 +0530 (Wed, 22 Jun 2016)");

  script_name("Jenkins Multiple Vulnerabilities (Feb 2015) - Linux");

  script_tag(name:"summary", value:"This host is installed with Jenkins and is prone to
  multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - The job configuration privilege to escalate his privileges, resulting in
    arbitrary code execution to the master.

  - The build script to access arbitrary files/directories on the master, resulting
    in the exposure of sensitive information, such as encryption keys.

  - The operation of Jenkins by feeding malicious update center data into Jenkins,
    affecting plugin installation and tool installation.

  - The read access to Jenkins to retrieve arbitrary XML document on the server,
    resulting in the exposure of sensitive information inside/outside Jenkins.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to obtain sensitive information, bypass the protection mechanism,
  gain elevated privileges, bypass intended access restrictions and execute arbitrary code.");

  script_tag(name:"affected", value:"Jenkins main line prior to 1.600, Jenkins LTS 1.580.3 and prior.");

  script_tag(name:"solution", value:"Main line users should upgrade to Jenkins 1.600,
  LTS users should upgrade to 1.596.1.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1205620");
  script_xref(name:"URL", value:"https://jenkins.io/security/advisory/2015-02-27/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_jenkins_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("jenkins/detected", "Host/runs_unixoide");

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
  if( version_is_less( version:version, test_version:"1.596.1" ) ) {
    vuln = TRUE;
    fix = "1.596.1";
  }
} else {
  if( version_is_less( version:version, test_version:"1.600" ) ) {
    vuln = TRUE;
    fix = "1.600";
  }
}

if( vuln ) {
  report = report_fixed_ver( installed_version:version, fixed_version:fix, install_path:location );
  security_message( port:port, data:report, proto:proto );
  exit( 0 );
}

exit( 99 );
