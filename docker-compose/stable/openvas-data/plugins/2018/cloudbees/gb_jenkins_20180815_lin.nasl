###############################################################################
# OpenVAS Vulnerability Test
#
# Jenkins < 2.138 and < 2.121.3 LTS Multiple Vulnerabilities - Linux
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112359");
  script_version("2021-06-29T11:00:37+0000");
  script_cve_id("CVE-2018-1999042", "CVE-2018-1999043", "CVE-2018-1999044", "CVE-2018-1999045",
  "CVE-2018-1999046", "CVE-2018-1999047");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2021-06-29 11:00:37 +0000 (Tue, 29 Jun 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-05-08 22:23:00 +0000 (Wed, 08 May 2019)");
  script_tag(name:"creation_date", value:"2018-08-27 10:30:00 +0200 (Mon, 27 Aug 2018)");

  script_name("Jenkins < 2.138 and < 2.121.3 LTS Multiple Vulnerabilities - Linux");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_jenkins_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("jenkins/detected", "Host/runs_unixoide");

  script_xref(name:"URL", value:"https://jenkins.io/security/advisory/2018-08-15/");

  script_tag(name:"summary", value:"This host is installed with Jenkins and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Jenkins is prone to the following vulnerabilities:

  - Jenkins allowed deserialization of URL objects via Remoting (agent communication) and XStream (CVE-2018-1999042).

  - Ephemeral user record was created on some invalid authentication attempts (CVE-2018-1999043).

  - Cron expression form validation could enter infinite loop, potentially resulting in denial of service (CVE-2018-1999044).

  - 'Remember me' cookie was evaluated even if that feature is disabled (CVE-2018-1999045).

  - Unauthorized users could access agent logs (CVE-2018-1999046).

  - Unauthorized users could cancel scheduled restarts initiated from the update center  (CVE-2018-1999047).");

  script_tag(name:"affected", value:"Jenkins LTS up to and including 2.121.2, Jenkins weekly up to and including 2.137.");

  script_tag(name:"solution", value:"Upgrade to Jenkins weekly to 2.138 or later / Jenkins LTS to 2.121.3 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

CPE = "cpe:/a:jenkins:jenkins";

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_full(cpe: CPE, port:port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];
proto = infos["proto"];

if( get_kb_item( "jenkins/" + port + "/is_lts" ) ) {
  if ( version_is_less( version:version, test_version:"2.121.3" ) ) {
    vuln = TRUE;
    fix = "2.121.3";
  }
} else {
  if( version_is_less( version:version, test_version:"2.138" ) ) {
    vuln = TRUE;
    fix = "2.138";
  }
}

if( vuln ) {
  report = report_fixed_ver( installed_version:version, fixed_version:fix, install_path:location );
  security_message( port:port, data:report, proto:proto );
  exit( 0 );
}

exit( 99 );
