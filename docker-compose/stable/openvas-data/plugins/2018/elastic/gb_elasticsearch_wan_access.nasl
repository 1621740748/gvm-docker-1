###############################################################################
# OpenVAS Vulnerability Test
#
# Elasticsearch Public WAN (Internet) Accessible
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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

CPE = "cpe:/a:elastic:elasticsearch";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108448");
  script_version("2021-01-18T10:09:47+0000");
  script_tag(name:"last_modification", value:"2021-01-18 10:09:47 +0000 (Mon, 18 Jan 2021)");
  script_tag(name:"creation_date", value:"2018-07-04 15:46:03 +0200 (Wed, 04 Jul 2018)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Elasticsearch Public WAN (Internet) Accessible");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_elastic_elasticsearch_detect_http.nasl", "global_settings.nasl");
  script_mandatory_keys("elastic/elasticsearch/noauth", "keys/is_public_addr");

  script_xref(name:"URL", value:"https://duo.com/blog/beyond-s3-exposed-resources-on-aws");

  script_tag(name:"summary", value:"The script checks if the target host is running an Elasticsearch
  service accessible from a public WAN (Internet).");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain
  access to sensitive information or modify system configuration.");

  script_tag(name:"vuldetect", value:"Evaluate if the target host is running an Elasticsearch
  service accessible from a public WAN (Internet).");

  script_tag(name:"solution", value:"Only allow access to the Elasticsearch service from trusted sources
  or enable authentication via the X-Pack Elastic Stack extension.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("host_details.inc");
include("network_func.inc");

if( ! is_public_addr() )
  exit( 0 );

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! get_kb_item( "elastic/elasticsearch/" + port + "/noauth" ) )
  exit( 99 );

get_app_location( cpe:CPE, port:port, nofork:TRUE );
security_message( port:port );
exit( 0 );
