# Copyright (C) 2009 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.800278");
  script_version("2021-04-07T07:28:15+0000");
  script_tag(name:"last_modification", value:"2021-04-07 07:28:15 +0000 (Wed, 07 Apr 2021)");
  script_tag(name:"creation_date", value:"2009-04-23 08:16:04 +0200 (Thu, 23 Apr 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2008-6504", "CVE-2008-6682");
  script_name("Apache Struts Multiple Vulnerabilities (S2-002, S2-003)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_apache_struts_consolidation.nasl");
  script_mandatory_keys("apache/struts/detected");

  script_xref(name:"URL", value:"https://cwiki.apache.org/confluence/display/WW/S2-002");
  script_xref(name:"URL", value:"https://cwiki.apache.org/confluence/display/WW/S2-003");
  script_xref(name:"Advisory-ID", value:"S2-002");
  script_xref(name:"Advisory-ID", value:"S2-003");

  script_tag(name:"summary", value:"Apache Struts is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the
  target host.");

  script_tag(name:"insight", value:"- CVE-2008-6504: OGNL provides, among other features,
  extensive expression evaluation capabilities. The vulnerability allows a malicious user
  to bypass the '#'-usage protection built into the ParametersInterceptor, thus being able
  to manipulate server side context objects.

  - CVE-2008-6682: This flaw is due to improper sanitization of the user supplied input in
  '<s:url>' and '<s:a>' tag which doesn't encode the URL parameter when specified in the
  action attribute which causes XSS attacks.");

  script_tag(name:"impact", value:"- CVE-2008-6504: Remote server context manipulation

  - CVE-2008-6682: Injection of malicious client side code");

  script_tag(name:"affected", value:"Apache Struts 2.0.0 through 2.1.8.1.");

  script_tag(name:"solution", value:"Update to version 2.2.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

vers = infos["version"];

if (version_in_range(version: vers, test_version: "2.0.0", test_version2: "2.2.0")) {
  report = report_fixed_ver(installed_version: vers, fixed_version: "2.2.1", install_path: infos["location"]);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);