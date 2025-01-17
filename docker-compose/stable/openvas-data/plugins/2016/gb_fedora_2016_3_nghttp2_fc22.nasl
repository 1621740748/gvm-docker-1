###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for nghttp2 FEDORA-2016-3
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.807282");
  script_version("2020-02-13T09:17:49+0000");
  script_tag(name:"last_modification", value:"2020-02-13 09:17:49 +0000 (Thu, 13 Feb 2020)");
  script_tag(name:"creation_date", value:"2016-02-23 06:25:09 +0100 (Tue, 23 Feb 2016)");
  script_cve_id("CVE-2016-1544");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for nghttp2 FEDORA-2016-3");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'nghttp2'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"affected", value:"nghttp2 on Fedora 22");
  script_tag(name:"solution", value:"Please install the updated package(s).");
  script_xref(name:"FEDORA", value:"2016-3");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/pipermail/package-announce/2016-February/177666.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC22");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "FC22")
{

  if ((res = isrpmvuln(pkg:"nghttp2", rpm:"nghttp2~1.7.1~1.fc22", rls:"FC22")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
