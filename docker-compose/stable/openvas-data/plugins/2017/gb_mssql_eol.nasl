###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft SQL Server End Of Life Detection
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH
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

CPE_PREFIX = "cpe:/a:microsoft:sql_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108188");
  script_version("2021-03-19T13:07:14+0000");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2021-03-19 13:07:14 +0000 (Fri, 19 Mar 2021)");
  script_tag(name:"creation_date", value:"2017-06-26 09:48:20 +0200 (Mon, 26 Jun 2017)");
  script_name("Microsoft SQL Server End Of Life Detection");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Databases");
  script_dependencies("mssqlserver_detect.nasl");
  script_mandatory_keys("MS/SQLSERVER/Running");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/lifecycle/search?sort=PN&alpha=sql%20server&Filter=FilterNO");
  script_xref(name:"URL", value:"https://en.wikipedia.org/wiki/History_of_Microsoft_SQL_Server#Release_summary");

  script_tag(name:"summary", value:"The Microsoft SQL Server version on the remote host has
  reached the end of life and should not be used anymore.");

  script_tag(name:"impact", value:"An end of life version of Microsoft SQL Server is not
  receiving any security updates from the vendor. Unfixed security vulnerabilities might
  be leveraged by an attacker to compromise the security of this host.");

  script_tag(name:"solution", value:"Update the Microsoft SQL Server version on the remote
  host to a still supported version.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("misc_func.inc");
include("products_eol.inc");
include("list_array_func.inc");
include("host_details.inc");

if( ! infos = get_app_port_from_cpe_prefix( cpe:CPE_PREFIX ) )
  exit( 0 );

port = infos["port"];
cpe = infos["cpe"];

if( ! version = get_app_version( cpe:cpe, port:port ) )
  exit( 0 );

if( ret = product_reached_eol( cpe:CPE_PREFIX, version:version ) ) {

  rls = get_kb_item( "MS/SQLSERVER/" + port + "/releasename" );

  report = build_eol_message( name:"Microsoft SQL Server " + rls,
                              cpe:cpe,
                              version:version,
                              eol_version:ret["eol_version"],
                              eol_date:ret["eol_date"],
                              eol_type:"prod" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
