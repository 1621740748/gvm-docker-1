###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for linux-firmware RHSA-2018:0094-01
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.910001");
  script_version("2021-06-30T11:00:43+0000");
  script_tag(name:"last_modification", value:"2021-06-30 11:00:43 +0000 (Wed, 30 Jun 2021)");
  script_tag(name:"creation_date", value:"2018-01-17 07:35:13 +0100 (Wed, 17 Jan 2018)");
  script_cve_id("CVE-2017-5715");
  script_tag(name:"cvss_base", value:"1.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-04-14 14:52:00 +0000 (Wed, 14 Apr 2021)");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for linux-firmware RHSA-2018:0094-01");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-firmware'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The linux-firmware packages contain all
of the firmware files that are required by various devices to operate.

This update supersedes microcode provided by Red Hat with the CVE-2017-5715
(Spectre) CPU branch injection vulnerability mitigation. (Historically,
Red Hat has provided updated microcode, developed by our microprocessor
partners, as a customer convenience.) Further testing has uncovered
problems with the microcode provided along with the Spectre mitigation
that could lead to system instabilities. As a result, Red Hat is providing
an microcode update that reverts to the last known good microcode version
dated before 03 January 2018. Red Hat strongly recommends that customers
contact their hardware provider for the latest microcode updates.

IMPORTANT: Customers using Intel Skylake-, Broadwell-, and Haswell-based
platforms must obtain and install updated microcode from their hardware
vendor immediately. The 'Spectre' mitigation requires both an updated
kernel from Red Hat and updated microcode from your hardware vendor.");
  script_tag(name:"affected", value:"linux-firmware on Red Hat Enterprise Linux Server (v. 7)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"RHSA", value:"2018:0094-01");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2018-January/msg00059.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_7");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_7")
{

  if ((res = isrpmvuln(pkg:"iwl100-firmware", rpm:"iwl100-firmware~39.31.5.1~58.el7_4", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"iwl1000-firmware", rpm:"iwl1000-firmware~39.31.5.1~58.el7_4", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"iwl105-firmware", rpm:"iwl105-firmware~18.168.6.1~58.el7_4", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"iwl135-firmware", rpm:"iwl135-firmware~18.168.6.1~58.el7_4", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"iwl2000-firmware", rpm:"iwl2000-firmware~18.168.6.1~58.el7_4", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"iwl2030-firmware", rpm:"iwl2030-firmware~18.168.6.1~58.el7_4", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"iwl3160-firmware", rpm:"iwl3160-firmware~22.0.7.0~58.el7_4", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"iwl3945-firmware", rpm:"iwl3945-firmware~15.32.2.9~58.el7_4", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"iwl4965-firmware", rpm:"iwl4965-firmware~228.61.2.24~58.el7_4", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"iwl5000-firmware", rpm:"iwl5000-firmware~8.83.5.1_1~58.el7_4", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"iwl5150-firmware", rpm:"iwl5150-firmware~8.24.2.2~58.el7_4", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"iwl6000-firmware", rpm:"iwl6000-firmware~9.221.4.1~58.el7_4", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"iwl6000g2a-firmware", rpm:"iwl6000g2a-firmware~17.168.5.3~58.el7_4", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"iwl6000g2b-firmware", rpm:"iwl6000g2b-firmware~17.168.5.2~58.el7_4", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"iwl6050-firmware", rpm:"iwl6050-firmware~41.28.5.1~58.el7_4", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"iwl7260-firmware", rpm:"iwl7260-firmware~22.0.7.0~58.el7_4", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"iwl7265-firmware", rpm:"iwl7265-firmware~22.0.7.0~58.el7_4", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"linux-firmware", rpm:"linux-firmware~20170606~58.gitc990aae.el7_4", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
