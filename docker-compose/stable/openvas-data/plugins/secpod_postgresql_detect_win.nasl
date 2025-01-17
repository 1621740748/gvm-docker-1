##############################################################################
# OpenVAS Vulnerability Test
#
# PostgreSQL Version Detection (Windows)
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
#
# Updated By: Shakeel <bshakeel@secpod.com> on 2014-07-15
# According to CR57 and new script style and to support 32 and 64 bit.
#
# Copyright:
# Copyright (C) 2009 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.900479");
  script_version("2020-01-28T13:26:39+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2020-01-28 13:26:39 +0000 (Tue, 28 Jan 2020)");
  script_tag(name:"creation_date", value:"2009-03-26 11:19:12 +0100 (Thu, 26 Mar 2009)");
  script_name("PostgreSQL Detection (Windows)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);

  script_xref(name:"URL", value:"https://www.postgresql.org/");

  script_tag(name:"summary", value:"This script detects the installed version of PostgreSQL.

  The script logs in via SMB, searches for PostgreSQL in the registry and gets
  version from registry.");

  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("smb_nt.inc");
include("secpod_smb_func.inc");

os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch)
  exit(0);

if("x86" >< os_arch) {
  key_list = make_list("SOFTWARE\PostgreSQL Global Development Group\PostgreSQL\");
}

else if("x64" >< os_arch) {
  key_list = make_list("SOFTWARE\PostgreSQL Global Development Group\PostgreSQL\",
                       "SOFTWARE\Wow6432Node\PostgreSQL Global Development Group\PostgreSQL\");
}

if(isnull(key_list))
  exit(0);

if(!registry_key_exists(key:"SOFTWARE\PostgreSQL")) {
  if(!registry_key_exists(key:"SOFTWARE\Wow6432Node\PostgreSQL")) {
    exit(0);
  }
}

foreach key(key_list) {

  insloc = registry_get_sz(key:key, item:"Location");
  if(insloc) {
    path = insloc + "\bin";
    vers = fetch_file_version(sysPath:path, file_name:"postgres.exe");
  } else {
    continue;
  }

  if(!isnull(vers)) {

    set_kb_item(name:"postgresql/detected", value:TRUE);

    cpe = build_cpe(value:vers, exp:"^([0-9.]+)", base:"cpe:/a:postgresql:postgresql:");
    if(!cpe)
      cpe = "cpe:/a:postgresql:postgresql";

    if("x64" >< os_arch && "Wow6432Node" >!< key) {
      cpe = build_cpe(value:vers, exp:"^([0-9.]+)", base:"cpe:/a:postgresql:postgresql:x64:");
      if(!cpe)
        cpe = "cpe:/a:postgresql:postgresql:x64";
    }

    register_product(cpe:cpe, location:insloc, port:0, service:"smb-login");

    log_message(data:build_detection_report(app:"PostgreSQL",
                                            version:vers,
                                            install:insloc,
                                            cpe:cpe,
                                            concluded:vers));

  }
}
