###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Internet Explorer 'msxml.dll' Information Disclosure Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (C) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.801876");
  script_version("2020-06-09T10:15:40+0000");
  script_tag(name:"last_modification", value:"2020-06-09 10:15:40 +0000 (Tue, 09 Jun 2020)");
  script_tag(name:"creation_date", value:"2011-04-22 16:38:12 +0200 (Fri, 22 Apr 2011)");
  script_cve_id("CVE-2011-1713");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_name("Microsoft Internet Explorer 'msxml.dll' Information Disclosure Vulnerability");
  script_xref(name:"URL", value:"http://scarybeastsecurity.blogspot.com/2011/03/multi-browser-heap-address-leak-in-xslt.html");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Windows");
  script_dependencies("gb_ms_ie_detect.nasl");
  script_mandatory_keys("MS/IE/Version");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to gain access to
  sensitive information that may aid in further attacks.");

  script_tag(name:"affected", value:"Microsoft Internet Explorer version 8 on Microsoft Windows 7.");

  script_tag(name:"insight", value:"The flaw is due to an error in msxml.dll allows remote attackers
  to obtain potentially sensitive information about heap memory addresses via an
  XML document containing a call to the XSLT generate-id XPath function.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"This host is installed with Internet Explorer and is prone to
  information disclosure vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");

if(hotfix_check_sp(win7:2) <= 0){
  exit(0);
}

ieVer = get_kb_item("MS/IE/Version");
if(!ieVer){
  exit(0);
}

if(version_in_range(version:ieVer, test_version:"8.0", test_version2:"8.0.7600.16766")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
