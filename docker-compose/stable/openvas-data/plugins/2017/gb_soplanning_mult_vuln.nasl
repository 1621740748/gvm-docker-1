##############################################################################
# OpenVAS Vulnerability Test
#
# Simple Online Planning < 1.33 Multiple Vulnerabilities
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
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

CPE = "cpe:/a:soplanning:soplanning";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112035");
  script_version("2020-08-12T08:55:31+0000");
  script_cve_id("CVE-2014-8673", "CVE-2014-8674", "CVE-2014-8675", "CVE-2014-8676", "CVE-2014-8677");
  script_bugtraq_id(75726);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-08-12 08:55:31 +0000 (Wed, 12 Aug 2020)");
  script_tag(name:"creation_date", value:"2017-09-04 12:34:59 +0200 (Mon, 04 Sep 2017)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Simple Online Planning < 1.33 Multiple Vulnerabilities");

  script_tag(name:"summary", value:"This host is running Simple Online Planning and is
  prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"SOPlanning version 1.32 and earlier.");

  script_tag(name:"solution", value:"Update to version 1.33 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2015/Jul/44");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_soplanning_detect.nasl");
  script_mandatory_keys("soplanning/detected");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE)) exit(0);
if(!vers = get_app_version(cpe:CPE, port:port)) exit(0);

if(version_is_less_equal(version:vers, test_version:"1.32")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"1.33");
  security_message(data:report, port:port);
  exit(0);
}
exit(99);
