###############################################################################
# OpenVAS Vulnerability Test
#
# TYPO3 Flowplayer Cross Site Scripting Vulnerability
#
# Authors:
# Shashi Kiran N <nskiran@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH
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
CPE = "cpe:/a:typo3:typo3";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803996");
  script_version("2020-02-17T08:23:05+0000");
  script_cve_id("CVE-2011-3642", "CVE-2013-1464");
  script_bugtraq_id(48651, 57848);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"last_modification", value:"2020-02-17 08:23:05 +0000 (Mon, 17 Feb 2020)");
  script_tag(name:"creation_date", value:"2014-01-02 11:15:58 +0530 (Thu, 02 Jan 2014)");
  script_name("TYPO3 Flowplayer Cross Site Scripting Vulnerability");


  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute script code.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"An error exists in the Flowplayer which fails to sufficiently
sanitize user supplied input to 'linkUrl' parameter.");
  script_tag(name:"solution", value:"Upgrade to TYPO3 version 4.5.29, 4.7.14, 6.0.8, 6.1.3 or later.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"This host is installed with TYPO3 and is prone to cross site scripting
vulnerability.");
  script_tag(name:"affected", value:"TYPO3 version 4.5.0 to 4.5.28, 4.7.0 to 4.7.13, 6.0.0 to 6.0.7 and 6.1.0 to 6.1.2");

  script_xref(name:"URL", value:"http://secunia.com/advisories/53529");
  script_xref(name:"URL", value:"http://typo3.org/teams/security/security-bulletins/typo3-core/typo3-core-sa-2013-002");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("gb_typo3_detect.nasl");
  script_mandatory_keys("TYPO3/installed");
  script_require_ports("Services/www", 80);
  exit(0);
}


include("version_func.inc");
include("host_details.inc");


if(!typoPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(typoVer = get_app_version(cpe:CPE, port:typoPort))
{
  if( typoVer !~ "[0-9]+\.[0-9]+\.[0-9]+" ) exit( 0 ); # Version is not exact enough
  if(version_in_range(version:typoVer, test_version:"4.5.0", test_version2:"4.5.28") ||
     version_in_range(version:typoVer, test_version:"4.7.0", test_version2:"4.7.13") ||
     version_in_range(version:typoVer, test_version:"6.0.0", test_version2:"6.0.7") ||
     version_in_range(version:typoVer, test_version:"6.1.0", test_version2:"6.1.2"))
  {
    security_message(typoPort);
    exit(0);
  }
}
