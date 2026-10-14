# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("db", "0122_alter_draftissue_assignees_alter_issue_assignees_and_more")]
    operations = [
        migrations.AlterField(
            model_name="account",
            name="provider",
            field=models.CharField(choices=[("oidc", "OIDC"), ("google", "Google"), ("github", "Github"), ("gitlab", "GitLab")]),
        ),
    ]
