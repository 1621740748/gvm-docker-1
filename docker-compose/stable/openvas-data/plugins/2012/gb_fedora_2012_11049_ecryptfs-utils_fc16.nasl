###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for ecryptfs-utils FEDORA-2012-11049
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_xref(name:"URL", value:"http://lists.fedoraproject.org/pipermail/package-announce/2012-August/084607.html");
  script_oid("1.3.6.1.4.1.25623.1.0.864600");
  script_version("2020-01-07T08:25:23+0000");
  script_tag(name:"last_modification", value:"2020-01-07 08:25:23 +0000 (Tue, 07 Jan 2020)");
  script_tag(name:"creation_date", value:"2012-08-06 11:22:40 +0530 (Mon, 06 Aug 2012)");
  script_cve_id("CVE-2012-3409");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_xref(name:"FEDORA", value:"2012-11049");
  script_name("Fedora Update for ecryptfs-utils FEDORA-2012-11049");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'ecryptfs-utils'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC16");
  script_tag(name:"affected", value:"ecryptfs-utils on Fedora 16");
  script_tag(name:"solution", value:"Please install the updated package(s).");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "FC16")
{

  if ((res = isrpmvuln(pkg:"ecryptfs-utils", rpm:"ecryptfs-utils~99~1.fc16", rls:"FC16")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
