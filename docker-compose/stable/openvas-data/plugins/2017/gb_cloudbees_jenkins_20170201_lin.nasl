###############################################################################
# OpenVAS Vulnerability Test
#
# Jenkins Multiple Vulnerabilities (Feb 2017) - Linux
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
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
  script_oid("1.3.6.1.4.1.25623.1.0.108095");
  script_version("2021-03-26T13:22:13+0000");
  script_cve_id("CVE-2011-4969", "CVE-2015-0886", "CVE-2017-2598", "CVE-2017-2599",
                "CVE-2017-2600", "CVE-2017-2601", "CVE-2017-2602", "CVE-2017-2603",
                "CVE-2017-2604", "CVE-2017-2605", "CVE-2017-2606", "CVE-2017-2607",
                "CVE-2017-2608", "CVE-2017-2609", "CVE-2017-2610", "CVE-2017-2611",
                "CVE-2017-2612", "CVE-2017-2613", "CVE-2017-1000362");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-03-26 13:22:13 +0000 (Fri, 26 Mar 2021)");
  script_tag(name:"creation_date", value:"2017-03-13 11:00:00 +0100 (Mon, 13 Mar 2017)");

  script_name("Jenkins Multiple Vulnerabilities (Feb 2017) - Linux");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_jenkins_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("jenkins/detected", "Host/runs_unixoide");

  script_xref(name:"URL", value:"https://jenkins.io/security/advisory/2017-02-01/");

  script_tag(name:"summary", value:"This host is installed with Jenkins and is prone to
  multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - cross-site scripting vulnerabilities

  - the usage ouf outdated libraries

  - insufficient access permission verifications / checks

  - a remote code execution vulnerability

  - an information disclosure vulnerability");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to obtain sensitive information,
  to bypass intended access restrictions and execute arbitrary code.");

  script_tag(name:"affected", value:"Jenkins LTS 2.32.1 and prior, Jenkins main line 2.43 and prior.");

  script_tag(name:"solution", value:"Upgrade to Jenkins main line to 2.44 or later / Jenkins LTS to 2.32.2 or
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
  if( version_is_less( version:version, test_version:"2.32.2" ) ) {
    vuln = TRUE;
    fix = "2.32.2";
  }
} else {
  if( version_is_less( version:version, test_version:"2.44" ) ) {
    vuln = TRUE;
    fix = "2.44";
  }
}

if( vuln ) {
  report = report_fixed_ver( installed_version:version, fixed_version:fix, install_path:location );
  security_message( port:port, data:report, proto:proto );
  exit( 0 );
}

exit( 99 );
