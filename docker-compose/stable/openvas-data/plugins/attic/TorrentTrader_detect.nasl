###############################################################################
# OpenVAS Vulnerability Test
#
# TorrentTrader Classic Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2009 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
  script_oid("1.3.6.1.4.1.25623.1.0.100180");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2020-04-02T11:36:28+0000");
  script_tag(name:"last_modification", value:"2020-04-02 11:36:28 +0000 (Thu, 02 Apr 2020)");
  script_tag(name:"creation_date", value:"2009-05-02 19:46:33 +0200 (Sat, 02 May 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("TorrentTrader Classic Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");

  script_xref(name:"URL", value:"http://www.torrenttrader.org/");

  script_tag(name:"summary", value:"This host is running TorrentTrader Classic, a PHP/MySQL Based
  BitTorrent tracker.

  This NVT has been replaced by NVT 'TorrentTrader Classic Version Detection' (OID: 1.3.6.1.4.1.25623.1.0.800525).");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit( 66 );
