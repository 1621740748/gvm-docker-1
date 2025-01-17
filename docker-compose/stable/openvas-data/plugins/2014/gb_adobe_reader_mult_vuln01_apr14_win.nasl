###############################################################################
# OpenVAS Vulnerability Test
#
# Adobe Reader Multiple Vulnerabilities - 01 Apr14 (Windows)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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

CPE = "cpe:/a:adobe:acrobat_reader";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804353");
  script_version("2020-10-20T15:03:35+0000");
  script_cve_id("CVE-2014-0511", "CVE-2014-0512");
  script_bugtraq_id(66205, 66512);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)");
  script_tag(name:"creation_date", value:"2014-01-21 14:00:20 +0530 (Tue, 21 Jan 2014)");
  script_name("Adobe Reader Multiple Vulnerabilities - 01 Apr14 (Windows)");

  script_tag(name:"summary", value:"This host is installed with Adobe Reader and is prone to multiple
vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Flaws are due to some unspecified errors.");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to bypass sandbox restrictions,
execute arbitrary code and compromise a user's system.");
  script_tag(name:"affected", value:"Adobe Reader XI version 11.0.6 and probably other versions on Windows.");
  script_tag(name:"solution", value:"Upgrade to version 11.0.07 or later.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://securitytracker.com/id?1029970");
  script_xref(name:"URL", value:"https://www.hkcert.org/my_url/en/alert/14033102");
  script_xref(name:"URL", value:"http://www.pwn2own.com/2014/03/pwn2own-results-for-wednesday-day-one");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_win.nasl");
  script_mandatory_keys("Adobe/Reader/Win/Installed");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!vers = get_app_version(cpe:CPE))
  exit(0);

if(vers && vers =~ "^11\.") {
  if(version_is_equal(version:vers, test_version:"11.0.6"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}
