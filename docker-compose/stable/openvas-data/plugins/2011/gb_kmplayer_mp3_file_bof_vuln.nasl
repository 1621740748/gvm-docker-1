###############################################################################
# OpenVAS Vulnerability Test
#
# KMPlayer '.mp3' File Remote Buffer Overflow Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.802208");
  script_version("2020-03-04T08:41:18+0000");
  script_bugtraq_id(48112);
  script_tag(name:"last_modification", value:"2020-03-04 08:41:18 +0000 (Wed, 04 Mar 2020)");
  script_tag(name:"creation_date", value:"2011-06-17 11:16:31 +0200 (Fri, 17 Jun 2011)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("KMPlayer '.mp3' File Remote Buffer Overflow Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/44825");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/67855");
  script_xref(name:"URL", value:"http://www.kmplayer.com/forums/showthread.php?p=87891");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/102196/km_pwn_aslr.py.txt");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);

  script_tag(name:"impact", value:"Successful exploitation allows attackers to execute arbitrary code
  in the context of the application. Failed attacks will cause denial-of-service conditions.");

  script_tag(name:"affected", value:"KMPlayer versions 3.0.0.1440 and prior.");

  script_tag(name:"insight", value:"The flaw is due to an error when processing MP3 files and can be
  exploited to cause a stack-based buffer overflow via a specially crafted file.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"This host is installed with KMPlayer and is prone to buffer
  overflow vulnerability.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion"))
  exit(0);

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\The KMPlayer";
if(!registry_key_exists(key:key))
  exit(0);

kmName = registry_get_sz(key:key, item:"DisplayName");
if("KMPlayer" >< kmName) {
  kmPath = registry_get_sz(key:key, item:"UninstallString");
  if(kmPath) {
    kmPath = ereg_replace(pattern:'\"(.*)\"', replace:"\1", string:kmPath);
    kmPath = ereg_replace(pattern:'uninstall.exe', replace:"KMPlayer.exe", string:kmPath);

    kmVer = fetch_file_version(sysPath:kmPath);
    if(!kmVer)
      exit(0);

    if(version_is_less_equal(version:kmVer, test_version:"3.0.0.1440")) {
      report = report_fixed_ver(installed_version:kmVer, fixed_version:"None", file_checked:kmPath);
      security_message(port:0, data:report);
      exit(0);
    }
  }
}

exit(99);
