# Copyright (C) 2010 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.801441");
  script_version("2021-04-01T07:54:37+0000");
  script_cve_id("CVE-2010-1870");
  script_bugtraq_id(41592);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2021-04-01 07:54:37 +0000 (Thu, 01 Apr 2021)");
  script_tag(name:"creation_date", value:"2010-09-10 16:37:50 +0200 (Fri, 10 Sep 2010)");
  script_name("Apache Struts/XWork RCE Vulnerability (S2-005)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_apache_struts_consolidation.nasl");
  script_mandatory_keys("apache/struts/detected");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/14360/");
  script_xref(name:"URL", value:"https://cwiki.apache.org/confluence/display/WW/S2-005");
  script_xref(name:"URL", value:"http://blog.o0o.nu/2010/07/cve-2010-1870-struts2xwork-remote.html");
  script_xref(name:"Advisory-ID", value:"S2-005");

  script_tag(name:"summary", value:"Apache Struts is prone to a remote command execution
  (RCE) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the
  target host.");

  script_tag(name:"insight", value:"The flaw is due to an error in 'OGNL' extensive
  expression evaluation capability in XWork in Struts, uses as permissive whitelist, which
  allows remote attackers to modify server-side context objects and bypass the '#'
  protection mechanism in ParameterInterceptors via various variables.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to
  manipulate server-side context objects with the privileges of the user running the
  application.");

  script_tag(name:"affected", value:"Apache Struts 2.0.0 through 2.1.8.1.");

  script_tag(name:"solution", value:"Update to version 2.2.1 or later.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

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