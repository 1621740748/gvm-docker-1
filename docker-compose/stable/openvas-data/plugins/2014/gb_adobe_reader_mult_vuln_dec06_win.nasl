###############################################################################
# OpenVAS Vulnerability Test
#
# Adobe Reader Multiple Vulnerabilities Dec06 (Windows)
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
  script_oid("1.3.6.1.4.1.25623.1.0.804366");
  script_version("2020-10-20T15:03:35+0000");
  script_cve_id("CVE-2006-6027", "CVE-2006-6236");
  script_bugtraq_id(21155, 21338);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)");
  script_tag(name:"creation_date", value:"2014-04-07 19:51:38 +0530 (Mon, 07 Apr 2014)");
  script_name("Adobe Reader Multiple Vulnerabilities Dec06 (Windows)");

  script_tag(name:"summary", value:"This host is installed with Adobe Reader and is prone to multiple
vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Flaws are due to errors in the 'AcroPDF ActiveX' control in AcroPDF.dll.");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to conduct denial of service,
possibly execute arbitrary code and compromise a user's system.");
  script_tag(name:"affected", value:"Adobe Reader version 7.0 through 7.0.8 on Windows.");
  script_tag(name:"solution", value:"Upgrade to Adobe Reader version 8.0 or later.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/23138");
  script_xref(name:"URL", value:"http://securitytracker.com/id?1017297");
  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/198908");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/30574");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb06-20.html");
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

if(vers && vers =~ "^7\.") {
  if(version_in_range(version:vers, test_version:"7.0", test_version2:"7.0.8"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}
