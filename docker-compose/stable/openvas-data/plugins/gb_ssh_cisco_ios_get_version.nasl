###############################################################################
# OpenVAS Vulnerability Test
#
# Report Cisco IOS Software Version
#
# Authors:
# Thomas Rotter <thomas.rotter@greenbone.net>
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.96206");
  script_version("2021-04-15T13:23:31+0000");
  script_tag(name:"last_modification", value:"2021-04-15 13:23:31 +0000 (Thu, 15 Apr 2021)");
  script_tag(name:"creation_date", value:"2011-06-06 16:48:59 +0200 (Mon, 06 Jun 2011)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Report Cisco IOS Software Version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_snmp_os_detection.nasl", "gb_cisco_ios_version_ssh.nasl");
  script_mandatory_keys("cisco_ios/detected");

  script_tag(name:"summary", value:"Report the Cisco IOS Software Version.");

  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("ssh_func.inc");
include("host_details.inc");
include("os_func.inc");

cpe = 'cpe:/o:cisco:ios';
version = 'unknown';

source = "ssh";

if( ! version = get_kb_item( "cisco_ios/" + source + "/version" ) )
{
  source = "snmp";
  if( ! version = get_kb_item( "cisco_ios/" + source + "/version" ) ) exit( 0 );
}

if( ! isnull( version ) )
{
  cpe += ':' + version;
  set_kb_item( name:'cisco_ios/version', value:version );
  set_kb_item(name: "SSH/Cisco/Version", value:version ); # for the old NVTs
}

if( model = get_kb_item( "cisco_ios/" + source + "/model")  )
{
  set_kb_item( name:'cisco_ios/model', value:model );
}

if( image = get_kb_item( "cisco_ios/" + source + "/image")  )
{
  set_kb_item( name:'cisco_ios/image', value:image );
}

register_product( cpe:cpe, location:source );
os_register_and_report( os:"Cisco IOS", cpe:cpe, banner_type:toupper( source ), desc:"Report Cisco IOS Software Version", runs_key:"unixoide" );

report = 'Detected Cisco IOS\n' +
         'Version: ' + version + '\n' +
         'CPE: ' + cpe + '\n';

if( model ) report += 'Model:   ' + model + '\n';
if( image ) report += 'Image:   ' + image + '\n';

report += 'Detection source: ' + source + '\n';

log_message( port:0, data:report );
exit( 0 );

