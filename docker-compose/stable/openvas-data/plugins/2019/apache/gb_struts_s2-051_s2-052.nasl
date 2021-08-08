# Copyright (C) 2019 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

CPE = "cpe:/a:apache:struts";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108624");
  script_version("2021-04-06T08:56:52+0000");
  script_cve_id("CVE-2017-9793", "CVE-2017-9805");
  script_bugtraq_id(100609, 100611);
  script_tag(name:"last_modification", value:"2021-04-06 08:56:52 +0000 (Tue, 06 Apr 2021)");
  script_tag(name:"creation_date", value:"2019-08-28 06:34:39 +0000 (Wed, 28 Aug 2019)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("Apache Struts Multiple Vulnerabilities (S2-051, S2-052)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_apache_struts_consolidation.nasl");
  script_mandatory_keys("apache/struts/detected");

  script_xref(name:"URL", value:"https://cwiki.apache.org/confluence/display/WW/S2-051");
  script_xref(name:"URL", value:"https://cwiki.apache.org/confluence/display/WW/S2-052");
  script_xref(name:"Advisory-ID", value:"S2-051");
  script_xref(name:"Advisory-ID", value:"S2-052");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100609");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100611");

  script_tag(name:"summary", value:"Apache Struts is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the
  target host.");

  script_tag(name:"insight", value:"- CVE-2017-9793: The REST Plugin is using outdated
  XStream library which is vulnerable and allow perform a DoS attack using malicious
  request with specially crafted XML payload.

  - CVE-2017-9805: The REST Plugin is using a XStreamHandler with an instance of XStream
  for deserialization without any type filtering and this can lead to Remote Code
  Execution when deserializing XML payloads.");

  script_tag(name:"impact", value:"- CVE-2017-9793: An attacker can exploit this issue to
  cause a DoS condition, denying service to legitimate users.

  - CVE-2017-9805: A RCE attack is possible when using the Struts REST plugin with XStream
  handler to deserialise XML requests.");

  script_tag(name:"affected", value:"Apache Struts 2.1.6 through 2.3.33 and 2.5 through
  2.5.12.");

  script_tag(name:"solution", value:"Update to version 2.3.34, 2.5.13 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if(!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

vers = infos["version"];

if(version_in_range(version: vers, test_version: "2.1.6", test_version2: "2.3.33")) {
  vuln = TRUE;
  fix = "2.3.34";
}

else if(version_in_range(version: vers, test_version: "2.5.0", test_version2: "2.5.12")) {
  vuln = TRUE;
  fix = "2.5.13";
}

if(vuln) {
  report = report_fixed_ver(installed_version: vers, fixed_version: fix, install_path: infos["location"]);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);