###############################################################################
# OpenVAS Vulnerability Test
#
# Jenkins Multiple Vulnerabilities (Nov 2017) - Linux
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.112130");
  script_version("2021-03-26T13:22:13+0000");

  script_cve_id("CVE-2017-1000391", "CVE-2017-1000392");

  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-03-26 13:22:13 +0000 (Fri, 26 Mar 2021)");
  script_tag(name:"creation_date", value:"2017-11-07 10:05:00 +0100 (Tue, 07 Nov 2017)");

  script_name("Jenkins Multiple Vulnerabilities (Nov 2017) - Linux");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_jenkins_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("jenkins/detected", "Host/runs_unixoide");

  script_xref(name:"URL", value:"https://jenkins.io/security/advisory/2017-11-08/");

  script_tag(name:"summary", value:"This host is installed with Jenkins and is prone to
  multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - unsafe use of user names as directory names

  - a persisted XSS vulnerability in autocompletion suggestions");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to
  affect the integrity of the application.");

  script_tag(name:"affected", value:"Jenkins LTS 2.73.2 and prior, Jenkins weekly up to and including 2.88.");

  script_tag(name:"solution", value:"Upgrade to Jenkins weekly to 2.89 or later / Jenkins LTS to 2.73.3 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
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
  if( version_is_less( version:version, test_version:"2.73.3" ) ) {
    vuln = TRUE;
    fix = "2.73.3";
  }
} else {
  if( version_is_less( version:version, test_version:"2.89" ) ) {
    vuln = TRUE;
    fix = "2.89";
  }
}

if( vuln ) {
  report = report_fixed_ver( installed_version:version, fixed_version:fix, install_path:location );
  security_message( port:port, data:report, proto:proto );
  exit( 0 );
}

exit( 99 );
