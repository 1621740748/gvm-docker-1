# Copyright (C) 2013 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804100");
  script_version("2021-06-11T09:28:25+0000");
  script_cve_id("CVE-2013-3934");
  script_bugtraq_id(31788);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2021-06-11 09:28:25 +0000 (Fri, 11 Jun 2021)");
  script_tag(name:"creation_date", value:"2013-09-26 09:21:06 +0530 (Thu, 26 Sep 2013)");
  script_name("Kingsoft Office Stack Buffer Overflow Vulnerability - Windows");

  script_tag(name:"summary", value:"Kingsoft Office is prone to a stack based buffer overflow
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"Upgrade to Kingsoft Office version 2013 9.1.0.4256 or later.");

  script_tag(name:"insight", value:"The flaw is due to a boundary error when handling font names.");

  script_tag(name:"affected", value:"Kingsoft Writer 2012 8.1.0.3030 used in Kingsoft Office 2013
  before 9.1.0.4256.");

  script_tag(name:"impact", value:"Successful exploitation will let attacker to execute arbitrary
  code via a long font name in a WPS file on the target users system which can cause a stack-based
  buffer overflow.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/53266");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1028920");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);

  exit(0);
}

include("smb_nt.inc");
include("host_details.inc");
include("version_func.inc");

if(!registry_key_exists(key:"SOFTWARE\Kingsoft\Office")){
 exit(0);
}

# nb: Cross check with Kingsoft Office installation
key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Kingsoft Office";
if(!registry_key_exists(key:key)){
  exit(0);
}

KingOffName = registry_get_sz(key:key, item:"DisplayName");

if("Kingsoft Office 2013" >< KingOffName)
{
  KingOffVer = registry_get_sz(key:key, item:"DisplayVersion");

  if(KingOffVer && version_is_less(version:KingOffVer, test_version:"9.1.0.4256"))
  {
    key2 = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Kingsoft Writer";
    if(!registry_key_exists(key:key2)){
      exit(0);
    }

    kingWrName = registry_get_sz(key:key2, item:"DisplayName");

    # nb: Cross check with Kingsoft Office Writer installation
    if("Kingsoft Writer" >< kingWrName)
    {
      kingWrVer = registry_get_sz(key:key2, item:"DisplayVersion");
      if(kingWrVer)
      {
        if(version_is_equal(version:kingWrVer, test_version:"8.1.0.3030"))
        {
          security_message( port: 0, data: "The target host was found to be vulnerable" );
          exit(0);
        }
      }
    }
  }
}
