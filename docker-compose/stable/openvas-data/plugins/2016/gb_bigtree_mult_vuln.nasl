###############################################################################
# OpenVAS Vulnerability Test
#
# BigTree CMS Multiple Vulnerabilities
#
# Authors:
# Tushar Khelge <ktushar@secpod.com>
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

CPE = "cpe:/a:bigtreecms:bigtree_cms";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807792");
  script_version("2020-02-27T10:48:22+0000");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2020-02-27 10:48:22 +0000 (Thu, 27 Feb 2020)");
  script_tag(name:"creation_date", value:"2016-04-18 14:17:30 +0530 (Mon, 18 Apr 2016)");
  script_name("BigTree CMS Multiple Vulnerabilities");

  script_tag(name:"summary", value:"The host is installed with BigTree CMS
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - An improper validation of input to 'cleanFile' Function.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to PHP object injection, and to bypass the filter.");

  script_tag(name:"affected", value:"BigTree CMS 4.2.8 and below.");

  script_tag(name:"solution", value:"Update to version 4.2.9 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2016/Mar/63");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_bigtree_detect.nasl");
  script_mandatory_keys("bigtree_cms/detected");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!vers = get_app_version(port:port, cpe:CPE))
  exit(0);

if(version_is_less_equal(version:vers, test_version:"4.2.8")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"4.2.9");
  security_message(data:report, port:port);
  exit(0);
}

exit(99);
