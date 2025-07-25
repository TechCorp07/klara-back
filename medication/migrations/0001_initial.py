# Generated by Django 4.2.7 on 2025-07-18 10:34

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import healthcare.fields


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('healthcare', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='Medication',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', healthcare.fields.EncryptedCharField()),
                ('generic_name', healthcare.fields.EncryptedCharField(blank=True, null=True)),
                ('ndc_code', healthcare.fields.EncryptedCharField(blank=True, help_text='National Drug Code', null=True)),
                ('rxnorm_code', healthcare.fields.EncryptedCharField(blank=True, help_text='RxNorm Code', null=True)),
                ('medication_type', models.CharField(choices=[('pill', 'Pill'), ('capsule', 'Capsule'), ('liquid', 'Liquid'), ('injection', 'Injection'), ('inhaler', 'Inhaler'), ('patch', 'Patch'), ('cream', 'Cream'), ('drops', 'Drops'), ('other', 'Other')], default='pill', max_length=20)),
                ('route', models.CharField(choices=[('oral', 'Oral'), ('intravenous', 'Intravenous'), ('intramuscular', 'Intramuscular'), ('subcutaneous', 'Subcutaneous'), ('topical', 'Topical'), ('inhalation', 'Inhalation'), ('ocular', 'Ocular'), ('nasal', 'Nasal'), ('rectal', 'Rectal'), ('other', 'Other')], default='oral', max_length=20)),
                ('dosage', healthcare.fields.EncryptedCharField()),
                ('dosage_unit', models.CharField(blank=True, max_length=50, null=True)),
                ('strength', healthcare.fields.EncryptedCharField(blank=True, null=True)),
                ('frequency', healthcare.fields.EncryptedCharField()),
                ('frequency_unit', models.CharField(choices=[('daily', 'Daily'), ('weekly', 'Weekly'), ('monthly', 'Monthly'), ('hourly', 'Hourly'), ('as_needed', 'As Needed'), ('custom', 'Custom')], default='daily', max_length=20)),
                ('times_per_frequency', models.PositiveSmallIntegerField(default=1)),
                ('specific_times', healthcare.fields.EncryptedJSONField(blank=True, help_text='JSON array of specific times for medication', null=True)),
                ('clinical_trial_id', models.CharField(blank=True, help_text='Associated clinical trial ID', max_length=100, null=True)),
                ('protocol_number', models.CharField(blank=True, help_text='Custom drug protocol number', max_length=100, null=True)),
                ('manufacturing_batch', models.CharField(blank=True, help_text='Batch number for custom drugs', max_length=100, null=True)),
                ('requires_lab_monitoring', models.BooleanField(default=False)),
                ('lab_monitoring_frequency', models.CharField(blank=True, choices=[('weekly', 'Weekly'), ('biweekly', 'Bi-weekly'), ('monthly', 'Monthly'), ('quarterly', 'Quarterly')], max_length=20, null=True)),
                ('storage_temperature', models.CharField(blank=True, help_text="e.g., 'Store at 2-8°C'", max_length=50)),
                ('special_handling_instructions', models.TextField(blank=True)),
                ('cost_per_dose', models.DecimalField(blank=True, decimal_places=2, max_digits=10, null=True)),
                ('insurance_coverage', models.BooleanField(default=False)),
                ('prior_authorization_required', models.BooleanField(default=False)),
                ('efficacy_markers', models.JSONField(default=list, help_text='Biomarkers to track for efficacy')),
                ('baseline_measurements', models.JSONField(default=dict, help_text='Baseline measurements before starting')),
                ('start_date', healthcare.fields.EncryptedDateField()),
                ('end_date', healthcare.fields.EncryptedDateField(blank=True, null=True)),
                ('ongoing', models.BooleanField(default=False)),
                ('instructions', healthcare.fields.EncryptedTextField(blank=True, null=True)),
                ('active', models.BooleanField(default=True)),
                ('for_rare_condition', models.BooleanField(default=False)),
                ('is_specialty_medication', models.BooleanField(default=False)),
                ('orphan_drug', models.BooleanField(default=False, help_text='Medication developed specifically for rare conditions')),
                ('prescription_required', models.BooleanField(default=True)),
                ('refills_allowed', models.PositiveSmallIntegerField(default=0)),
                ('refills_remaining', models.PositiveSmallIntegerField(default=0)),
                ('last_refill_date', models.DateField(blank=True, null=True)),
                ('pharmacy_name', healthcare.fields.EncryptedCharField(blank=True, null=True)),
                ('pharmacy_phone', healthcare.fields.EncryptedCharField(blank=True, null=True)),
                ('potential_side_effects', healthcare.fields.EncryptedTextField(blank=True, null=True)),
                ('known_interactions', healthcare.fields.EncryptedTextField(blank=True, null=True)),
                ('adherence_schedule', models.JSONField(blank=True, default=dict, help_text='Scheduled times for adherence tracking')),
                ('last_reminded_at', models.DateTimeField(blank=True, null=True)),
                ('fhir_resource_id', models.CharField(blank=True, max_length=100, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('condition', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='medications', to='healthcare.condition')),
                ('created_by', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='medication_created_medications', to=settings.AUTH_USER_MODEL)),
                ('medical_record', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='medication_medications', to='healthcare.medicalrecord')),
                ('patient', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='medications', to=settings.AUTH_USER_MODEL)),
                ('prescriber', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='medication_prescribed_medications', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'verbose_name': 'Medication',
                'verbose_name_plural': 'Medications',
                'ordering': ['-updated_at'],
            },
        ),
        migrations.CreateModel(
            name='SideEffect',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('description', healthcare.fields.EncryptedTextField()),
                ('severity', models.CharField(choices=[('mild', 'Mild'), ('moderate', 'Moderate'), ('severe', 'Severe'), ('life_threatening', 'Life Threatening')], default='mild', max_length=20)),
                ('onset_date', models.DateField()),
                ('resolution_date', models.DateField(blank=True, null=True)),
                ('ongoing', models.BooleanField(default=True)),
                ('reported_to_doctor', models.BooleanField(default=False)),
                ('doctor_notified_date', models.DateField(blank=True, null=True)),
                ('medication_adjusted', models.BooleanField(default=False)),
                ('medication_stopped', models.BooleanField(default=False)),
                ('notes', healthcare.fields.EncryptedTextField(blank=True, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('created_by', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='created_side_effects', to=settings.AUTH_USER_MODEL)),
                ('medication', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='side_effects', to='medication.medication')),
                ('patient', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='reported_side_effects', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'verbose_name': 'Side Effect',
                'verbose_name_plural': 'Side Effects',
                'ordering': ['-onset_date'],
            },
        ),
        migrations.CreateModel(
            name='Prescription',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('prescription_number', healthcare.fields.EncryptedCharField(unique=True)),
                ('status', models.CharField(choices=[('pending', 'Pending'), ('active', 'Active'), ('filled', 'Filled'), ('expired', 'Expired'), ('cancelled', 'Cancelled'), ('completed', 'Completed')], default='pending', max_length=20)),
                ('prescribed_date', models.DateField()),
                ('fill_date', models.DateField(blank=True, null=True)),
                ('expiration_date', models.DateField(blank=True, null=True)),
                ('medication_name', healthcare.fields.EncryptedCharField()),
                ('dosage', healthcare.fields.EncryptedCharField()),
                ('frequency', healthcare.fields.EncryptedCharField()),
                ('quantity', healthcare.fields.EncryptedCharField()),
                ('refills', models.PositiveSmallIntegerField(default=0)),
                ('pharmacy_name', healthcare.fields.EncryptedCharField(blank=True, null=True)),
                ('pharmacy_phone', healthcare.fields.EncryptedCharField(blank=True, null=True)),
                ('pharmacy_address', healthcare.fields.EncryptedTextField(blank=True, null=True)),
                ('is_electronic', models.BooleanField(default=False)),
                ('electronic_routing_id', healthcare.fields.EncryptedCharField(blank=True, null=True)),
                ('instructions', healthcare.fields.EncryptedTextField(blank=True, null=True)),
                ('notes', healthcare.fields.EncryptedTextField(blank=True, null=True)),
                ('fhir_resource_id', models.CharField(blank=True, max_length=100, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('created_by', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='created_prescriptions', to=settings.AUTH_USER_MODEL)),
                ('patient', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='prescriptions', to=settings.AUTH_USER_MODEL)),
                ('prescriber', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='medication_provider_prescriptions', to=settings.AUTH_USER_MODEL)),
                ('updated_by', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='updated_prescriptions', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'verbose_name': 'Prescription',
                'verbose_name_plural': 'Prescriptions',
                'ordering': ['-prescribed_date'],
            },
        ),
        migrations.CreateModel(
            name='MedicationReminder',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('reminder_type', models.CharField(choices=[('dose', 'Dose Reminder'), ('refill', 'Refill Reminder'), ('appointment', 'Appointment Reminder'), ('lab', 'Lab Test Reminder')], default='dose', max_length=20)),
                ('message', healthcare.fields.EncryptedTextField()),
                ('frequency', models.CharField(choices=[('once', 'Once'), ('daily', 'Daily'), ('weekly', 'Weekly'), ('monthly', 'Monthly'), ('custom', 'Custom')], default='daily', max_length=20)),
                ('scheduled_time', models.DateTimeField()),
                ('recurrence_pattern', models.CharField(blank=True, help_text='iCal RRULE format', max_length=255, null=True)),
                ('window_before', models.PositiveIntegerField(default=0, help_text='Minutes before scheduled time to start sending reminders')),
                ('window_after', models.PositiveIntegerField(default=0, help_text='Minutes after scheduled time to stop sending reminders')),
                ('is_active', models.BooleanField(default=True)),
                ('last_sent', models.DateTimeField(blank=True, null=True)),
                ('send_email', models.BooleanField(default=True)),
                ('send_push', models.BooleanField(default=True)),
                ('send_sms', models.BooleanField(default=False)),
                ('send_smartwatch', models.BooleanField(default=False)),
                ('smartwatch_delivery_confirmed', models.BooleanField(default=False)),
                ('is_critical', models.BooleanField(default=False, help_text='Critical reminder for rare disease medication')),
                ('escalation_enabled', models.BooleanField(default=False, help_text='Escalate to provider if missed')),
                ('escalation_delay_minutes', models.PositiveIntegerField(default=60, help_text='Minutes before escalating')),
                ('times_sent', models.PositiveIntegerField(default=0)),
                ('patient_acknowledged', models.BooleanField(default=False)),
                ('acknowledged_at', models.DateTimeField(blank=True, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('created_by', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='created_medication_reminders', to=settings.AUTH_USER_MODEL)),
                ('medication', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='reminders', to='medication.medication')),
                ('patient', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='medication_reminders', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'verbose_name': 'Medication Reminder',
                'verbose_name_plural': 'Medication Reminders',
                'ordering': ['scheduled_time'],
            },
        ),
        migrations.CreateModel(
            name='MedicationIntake',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('scheduled_time', models.DateTimeField()),
                ('actual_time', models.DateTimeField(blank=True, null=True)),
                ('status', models.CharField(choices=[('taken', 'Taken'), ('skipped', 'Skipped'), ('missed', 'Missed'), ('rescheduled', 'Rescheduled')], default='missed', max_length=20)),
                ('dosage_taken', healthcare.fields.EncryptedCharField(blank=True, null=True)),
                ('skip_reason', healthcare.fields.EncryptedTextField(blank=True, null=True)),
                ('notes', healthcare.fields.EncryptedTextField(blank=True, null=True)),
                ('recorded_via', models.CharField(blank=True, help_text='app, wearable, caregiver, etc.', max_length=50)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('medication', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='intakes', to='medication.medication')),
                ('recorded_by', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='recorded_intakes', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'verbose_name': 'Medication Intake',
                'verbose_name_plural': 'Medication Intakes',
                'ordering': ['-scheduled_time'],
            },
        ),
        migrations.AddField(
            model_name='medication',
            name='prescription',
            field=models.OneToOneField(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='medication', to='medication.prescription'),
        ),
        migrations.AddField(
            model_name='medication',
            name='updated_by',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='updated_medications', to=settings.AUTH_USER_MODEL),
        ),
        migrations.CreateModel(
            name='AdherenceRecord',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('period_type', models.CharField(choices=[('daily', 'Daily'), ('weekly', 'Weekly'), ('monthly', 'Monthly'), ('quarterly', 'Quarterly'), ('yearly', 'Yearly')], default='weekly', max_length=20)),
                ('period_start', models.DateField()),
                ('period_end', models.DateField()),
                ('doses_scheduled', models.PositiveIntegerField(default=0)),
                ('doses_taken', models.PositiveIntegerField(default=0)),
                ('doses_skipped', models.PositiveIntegerField(default=0)),
                ('doses_missed', models.PositiveIntegerField(default=0)),
                ('adherence_rate', models.FloatField(default=0.0, help_text='Percentage of doses taken on time')),
                ('average_delay', models.FloatField(default=0.0, help_text='Average minutes late for doses')),
                ('notes', healthcare.fields.EncryptedTextField(blank=True, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('medication', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='adherence_records', to='medication.medication')),
                ('patient', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='adherence_records', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'verbose_name': 'Adherence Record',
                'verbose_name_plural': 'Adherence Records',
                'ordering': ['-period_start'],
            },
        ),
        migrations.CreateModel(
            name='DrugInteraction',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('description', healthcare.fields.EncryptedTextField()),
                ('severity', models.CharField(choices=[('minor', 'Minor'), ('moderate', 'Moderate'), ('major', 'Major'), ('contraindicated', 'Contraindicated')], default='moderate', max_length=20)),
                ('detected_date', models.DateField(auto_now_add=True)),
                ('resolved_date', models.DateField(blank=True, null=True)),
                ('resolution_action', healthcare.fields.EncryptedTextField(blank=True, null=True)),
                ('patient_notified', models.BooleanField(default=False)),
                ('provider_notified', models.BooleanField(default=False)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('created_by', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='created_interactions', to=settings.AUTH_USER_MODEL)),
                ('medication_a', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='interactions_as_a', to='medication.medication')),
                ('medication_b', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='interactions_as_b', to='medication.medication')),
                ('patient', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='drug_interactions', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'verbose_name': 'Drug Interaction',
                'verbose_name_plural': 'Drug Interactions',
                'ordering': ['-detected_date'],
                'unique_together': {('medication_a', 'medication_b', 'patient')},
            },
        ),
    ]
