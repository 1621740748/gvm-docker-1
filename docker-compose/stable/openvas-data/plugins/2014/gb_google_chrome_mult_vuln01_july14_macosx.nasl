###############################################################################
# OpenVAS Vulnerability Test
#
# Google Chrome Multiple Vulnerabilities - 01 July14 (Mac OS X)
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804728");
  script_version("2020-04-20T13:31:49+0000");
  script_cve_id("CVE-2014-3160", "CVE-2014-3162");
  script_bugtraq_id(68677);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-04-20 13:31:49 +0000 (Mon, 20 Apr 2020)");
  script_tag(name:"creation_date", value:"2014-08-01 18:43:05 +0530 (Fri, 01 Aug 2014)");
  script_name("Google Chrome Multiple Vulnerabilities - 01 July14 (Mac OS X)");


  script_tag(name:"summary", value:"The host is installed with Google Chrome and is prone to multiple
vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Multiple flaws are due to An error within SVG component and multiple
unspecified errors exist.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to bypass certain
security restrictions and possibly have other unspecified impact.");
  script_tag(name:"affected", value:"Google Chrome version prior to 36.0.1985.125 on Mac OS X.");
  script_tag(name:"solution", value:"Upgrade to Google Chrome 36.0.1985.125 or later.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/60077");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/2014/07/stable-channel-update.html");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_google_chrome_detect_macosx.nasl");
  script_mandatory_keys("GoogleChrome/MacOSX/Version");

  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!chromeVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:chromeVer, test_version:"36.0.1985.125"))
{
  report = report_fixed_ver(installed_version:chromeVer, fixed_version:"36.0.1985.125");
  security_message(port:0, data:report);
  exit(0);
}
