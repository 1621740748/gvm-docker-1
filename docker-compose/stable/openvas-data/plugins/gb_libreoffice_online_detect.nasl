###############################################################################
# OpenVAS Vulnerability Test
#
# LibreOffice Online Detection
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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
  script_oid("1.3.6.1.4.1.25623.1.0.108000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2021-07-05T06:08:17+0000");
  script_tag(name:"last_modification", value:"2021-07-05 06:08:17 +0000 (Mon, 05 Jul 2021)");
  script_tag(name:"creation_date", value:"2016-09-15 09:00:00 +0200 (Thu, 15 Sep 2016)");
  script_name("LibreOffice Online Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 9980);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://wiki.documentfoundation.org/Development/LibreOffice_Online");

  script_tag(name:"summary", value:"HTTP based detection of LibreOffice Online.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("cpe.inc");
include("host_details.inc");

port = http_get_port( default:9980 );
host = http_host_name( dont_add_port:TRUE );

foreach dir( make_list_unique( "/", http_cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";

  url = dir + "/hosting/discovery";
  buf = http_get_cache( item:url, port:port );

  # User-Agent: LOOLWSD HTTP Agent 6.4.10
  # User-Agent: LOOLWSD WOPI Agent 4.2.15
  if( buf =~ "^HTTP/1\.[01] 200" && ( buf =~ "User-Agent\s*:\s*LOOLWSD (WOPI|HTTP) Agent" ||
      ( "wopi-discovery" >< buf && "application/vnd." >< buf && "loleaflet.html" >< buf ) ) ) {

    version = "unknown";
    concludedUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );
    reportUrl = 'The following URLs were identified:\n\n' +
                http_report_vuln_url( port:port, url:url, url_only:TRUE ) + '\n';

    # TODO: Find a way to detect the LOOL version. This format has changed in between releases
    # and is e.g. currently only returning something like 8a1761a as a version.
    #verUrl = egrep( string:buf, pattern:'<action ext="lwp" name=".*" urlsrc=".*"/>', icase:TRUE );
    #ver = eregmatch( string:verUrl, pattern:'urlsrc="(https?://.*/([0-9.]+)/.*)"/>', icase:TRUE );
    #if( ! isnull( ver[2] ) ) {
    #  version = ver[2];
    #  reportUrl += ver[1] + '\n';
    #}

    #Basic auth check for default_http_auth_credentials.nasl
    foreach url( make_list( dir + "/dist/admin/admin.html", dir + "/loleaflet/dist/admin/admin.html" ) ) {

      buf2 = http_get_cache( item:url, port:port );

      if( buf2 =~ "^HTTP/1\.[01] 401" ) {
        set_kb_item( name:"www/content/auth_required", value:TRUE );
        set_kb_item( name:"www/" + host + "/" + port + "/content/auth_required", value:url );
        reportUrl += http_report_vuln_url( port:port, url:url, url_only:TRUE ) + '\n';
        break;
      }
    }

    tmp_version = version + " under " + install;
    set_kb_item( name:"www/" + port + "/LibreOfficeOnline", value:tmp_version );
    set_kb_item( name:"LibreOfficeOnline/installed", value:TRUE );

    # CPE not registered yet
    cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:collabora:libreofficeonline:" );
    if( ! cpe )
      cpe = "cpe:/a:collabora:libreofficeonline";

    register_product( cpe:cpe, location:install, port:port, service:"www" );

    log_message( data:build_detection_report( app:"LibreOffice Online",
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              # concluded:ver[0], # nb: Re-add this once the version check above was re-implemented
                                              concludedUrl:concludedUrl,
                                              extra:reportUrl ),
                                              port:port );
  }
}

exit( 0 );