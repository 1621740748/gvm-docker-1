###############################################################################
# OpenVAS Vulnerability Test
#
# SDP Downloader Version Detection
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.900641");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2019-11-05T16:13:01+0000");
  script_tag(name:"last_modification", value:"2019-11-05 16:13:01 +0000 (Tue, 05 Nov 2019)");
  script_tag(name:"creation_date", value:"2009-05-20 10:26:22 +0200 (Wed, 20 May 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("SDP Downloader Version Detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_tag(name:"summary", value:"This script detects the installed version of SDP Downloader.");
  exit(0);
}

include("smb_nt.inc");
include("secpod_smb_func.inc");
include("cpe.inc");
include("host_details.inc");

SCRIPT_DESC = "SDP Downloader Version Detection";

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

sdpKey = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";

if(!registry_key_exists(key:sdpKey)){
    exit(0);
}

foreach item(registry_enum_keys(key:sdpKey))
{
  sdpName = registry_get_sz(key:sdpKey + item, item:"DisplayName");

  if("SDP Downloader" >< sdpName)
  {
    sdpVer = registry_get_sz(key:sdpKey + item, item:"DisplayVersion");
    if(sdpVer){
      set_kb_item(name:"SDP/Downloader/Ver", value:sdpVer);
      log_message(data:"SDP Downloader version " + sdpVer +
                         " was detected on the host");

      cpe = build_cpe(value:sdpVer, exp:"^([0-9.]+)", base:"cpe:/a:sdp_multimedia:streaming_download_project:");
      if(!isnull(cpe))
         register_host_detail(name:"App", value:cpe, desc:SCRIPT_DESC);

    }
    exit(0);
  }
}
