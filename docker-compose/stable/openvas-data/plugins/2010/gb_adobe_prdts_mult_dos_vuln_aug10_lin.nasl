###############################################################################
# OpenVAS Vulnerability Test
#
# Adobe Flash Player/Air Multiple Vulnerabilities - August10 (Linux)
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.801256");
  script_version("2020-10-20T15:03:35+0000");
  script_tag(name:"last_modification", value:"2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)");
  script_tag(name:"creation_date", value:"2010-08-16 09:09:42 +0200 (Mon, 16 Aug 2010)");
  script_cve_id("CVE-2010-0209", "CVE-2010-2213", "CVE-2010-2215",
                "CVE-2010-2214", "CVE-2010-2216");
  script_bugtraq_id(42341);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Adobe Flash Player/Air Multiple Vulnerabilities - August10 (Linux)");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb10-16.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_adobe_flash_player_detect_lin.nasl");
  script_mandatory_keys("Adobe/Air_or_Flash_or_Reader/Linux/Installed");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary code,
  cause denial-of-service conditions, or perform click-jacking attacks.");

  script_tag(name:"affected", value:"Adobe AIR version prior to 2.0.3

  Adobe Flash Player version before 9.0.280 and 10.x before 10.1.82.76 on Linux");

  script_tag(name:"insight", value:"The flaws are due to memory corruptions and click-jacking issue via
  unspecified vectors.");

  script_tag(name:"solution", value:"Upgrade to Adobe Air 2.0.3 and Adobe Flash Player 9.0.280 or 10.1.82.76 or later.");

  script_tag(name:"summary", value:"This host is installed with Adobe Flash Player/Air and is prone to
  multiple vulnerabilities.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");


  exit(0);
}

include("version_func.inc");

vers = get_kb_item("AdobeFlashPlayer/Linux/Ver");
if(vers) {
  if(version_is_less(version:vers, test_version:"9.0.280") ||
     version_in_range(version:vers, test_version:"10.0", test_version2:"10.1.82.75"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

vers = get_kb_item("Adobe/Air/Linux/Ver");
if(vers) {
  if(version_is_less(version:vers, test_version:"2.0.3")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
