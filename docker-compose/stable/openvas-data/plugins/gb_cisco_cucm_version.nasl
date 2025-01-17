###############################################################################
# OpenVAS Vulnerability Test
#
# Cisco Unified Communications Manager Detect
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105540");
  script_version("2021-04-15T13:23:31+0000");
  script_tag(name:"last_modification", value:"2021-04-15 13:23:31 +0000 (Thu, 15 Apr 2021)");
  script_tag(name:"creation_date", value:"2016-02-12 12:35:56 +0100 (Fri, 12 Feb 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Cisco Unified Communications Manager Detect");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("cisco/cucm/detected");

  script_tag(name:"summary", value:"This script performs ssh based detection of Cisco Unified Communications Manager");

  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("host_details.inc");
include("os_func.inc");
include("ssh_func.inc");

if( ! get_kb_item( "cisco/cucm/detected" ) ) exit( 0 );

sock = ssh_login_or_reuse_connection();
if( ! sock ) exit( 0 );

show_ver = ssh_cmd( socket:sock, cmd:'show version active', nosh:TRUE, pty:TRUE, timeout:60, retry:30, pattern:"Active Master Version:" );

if( ! show_ver || "Active Master Version:" >!< show_ver ) exit( 0 );

cpe = 'cpe:/a:cisco:unified_communications_manager';
ucos_cpe = 'cpe:/o:cisco:ucos';

vers = 'unknown';

version = eregmatch( pattern:'Active Master Version: ([^\r\n]+)', string:show_ver );
if( ! isnull( version[1] ) )
{
  vers = version[1];
  set_kb_item( name:'cisco/cucm/version', value:vers );
  cpe += ':' + vers;
  ucos_cpe += ':' + vers;
}

register_product( cpe:cpe, location:'ssh' );

os_register_and_report( os:"Cisco UCOS", cpe:ucos_cpe, banner_type:"SSH login", desc:"Cisco Unified Communications Manager Detect", runs_key:"unixoide" );

log_message( data: build_detection_report( app:'Cisco Unified Communications Manager',
                                           version:vers,
                                           install:'ssh',
                                           cpe:cpe,
                                           concluded: 'show version active' ),
             port:0 );

exit( 0 );

