##############################################################################
# OpenVAS Vulnerability Test
#
# ISC BIND Unusual DS Record Response Denial of Service Vulnerability - Linux
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:isc:bind";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810284");
  script_version("2021-03-26T13:22:13+0000");
  script_cve_id("CVE-2016-9444");
  script_bugtraq_id(95393);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2021-03-26 13:22:13 +0000 (Fri, 26 Mar 2021)");
  script_tag(name:"creation_date", value:"2017-01-16 16:59:09 +0530 (Mon, 16 Jan 2017)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("ISC BIND Unusual DS Record Response Denial of Service Vulnerability - Linux");

  script_tag(name:"summary", value:"ISC BIND is prone to a denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an error in the
  processing of an unusually-formed answer containing a DS resource record
  received in response to a query.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause a denial of service (assertion failure and daemon exit) via
  crafted data.");

  script_tag(name:"affected", value:"ISC BIND 9.6-ESV-R9 through 9.6-ESV-R11-W1,
  9.8.5 through 9.8.8, 9.9.3 through 9.9.9-P4, 9.9.9-S1 through 9.9.9-S6, 9.10.0 through
  9.10.4-P4 and 9.11.0 through 9.11.0-P1.");

  script_tag(name:"solution", value:"Update to ISC BIND version 9.9.9-P5 or
  9.10.4-P5 or 9.11.0-P2 or 9.9.9-S7 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://kb.isc.org/docs/aa-01441");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_isc_bind_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("isc/bind/detected", "Host/runs_unixoide");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");
include("revisions-lib.inc");

if(isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if(!infos = get_app_full(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

version = infos["version"];
proto = infos["proto"];
location = infos["location"];

if(version =~ "^9\.") {
  if(version_in_range(version:version, test_version:"9.8.5", test_version2:"9.8.8")) {
    fix = "9.9.9-P5";
    VULN = TRUE;
  }

  else if(version =~ "^9\.6") {
    if ((revcomp(a: version, b: "9.6r9") >= 0) && (revcomp(a: version, b: "9.6r11-w2") < 0)) {
      fix = "9.9.9-P5";
      VULN = TRUE;
    }
  }

  if (version =~ "^9\.9\.[3-9]") {
    if(revcomp(a: version, b: "9.9.9p5") < 0) {
      fix = "9.9.9-P5";
      VULN = TRUE;
    }
  }
  else if(version =~ "^9\.9\.9s[1-6]") {
    fix = "9.9.9-S7";
    VULN = TRUE;
  }

  else if(version =~ "^9\.10\.") {
    if(revcomp(a: version, b: "9.10.4p5") < 0) {
      fix = "9.10.4-P5";
      VULN = TRUE;
    }
  }
  else if(version =~ "^9\.11\.0") {
    if(revcomp(a: version, b: "9.11.0p2") < 0) {
      fix = "9.11.0-P2";
      VULN = TRUE;
    }
  }
}

if(VULN) {
  report = report_fixed_ver(installed_version:version, fixed_version:fix, install_path:location);
  security_message(data:report, port:port, proto:proto);
  exit(0);
}

exit(99);
