###############################################################################
# OpenVAS Vulnerability Test
#
# Cisco Mobility Services Engine: Default Password `XmlDba123` for `oracle` account.
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH
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
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140114");
  script_bugtraq_id(77432);
  script_cve_id("CVE-2015-6316");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_version("2020-08-24T08:40:10+0000");

  script_name("Cisco Mobility Services Engine: Default Password `XmlDba123` for `oracle` account.");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20151104-mse-cred");

  script_tag(name:"vuldetect", value:"Try to login as user 'oracle'.");

  script_tag(name:"insight", value:"This issues are being tracked by Cisco Bug ID CSCuv40501 and CSCuv40504.");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");

  script_tag(name:"summary", value:"The remote Cisco Mobility Services Engine is prone to an insecure default-password vulnerability.");

  script_tag(name:"impact", value:"Remote attackers with knowledge of the default credentials may exploit this vulnerability to gain unauthorized
  access and perform unauthorized actions. This may aid in further attacks.");

  script_tag(name:"affected", value:"Cisco Mobility Services Engine (MSE) versions 8.0.120.7 and earlier are vulnerable.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"last_modification", value:"2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2017-01-03 13:09:00 +0100 (Tue, 03 Jan 2017)");
  script_category(ACT_ATTACK);
  script_family("CISCO");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("ssh_detect.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/ssh", 22);
  script_mandatory_keys("ssh/server_banner/available");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  exit(0);
}

include("ssh_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

if( get_kb_item( "default_credentials/disable_default_account_checks" ) )
  exit( 0 );

port = ssh_get_port( default:22 );

if( ! soc = open_sock_tcp( port ) )
  exit( 0 );

user = 'oracle';
pass = 'XmlDba123';

login = ssh_login( socket:soc, login:user, password:pass, priv:NULL, passphrase:NULL );
if(login == 0)
{
  cmd = 'id';
  res = ssh_cmd( socket:soc, cmd:cmd );
  close( soc );

  if( res =~ "uid=[0-9]+.*gid=[0-9]+" )
  {
    report = 'It was possible to login as user "' + user + '" with password "' + pass + '" and to execute the "' + cmd + '" command. Result:\n\n' + res;
    security_message( port:port, data:report );
    exit( 0 );
  }
}

if( soc ) close( soc );
exit( 0 );
