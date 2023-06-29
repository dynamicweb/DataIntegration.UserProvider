﻿using Dynamicweb.Data;
using Dynamicweb.DataIntegration.Integration;
using Dynamicweb.DataIntegration.Integration.Interfaces;
using Dynamicweb.DataIntegration.ProviderHelpers;
using Dynamicweb.Extensibility;
using Dynamicweb.Extensibility.AddIns;
using Dynamicweb.Extensibility.Editors;
using Dynamicweb.Indexing;
using Dynamicweb.Indexing.Repositories;
using Dynamicweb.Logging;
using Dynamicweb.Security.Permissions;
using Dynamicweb.Security.UserManagement;
using Dynamicweb.Security.UserManagement.Common.SystemFields;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Data.SqlClient;
using System.Globalization;
using System.Linq;
using System.Xml;
using System.Xml.Linq;

namespace Dynamicweb.DataIntegration.Providers.UserProvider
{
    [AddInName("Dynamicweb.DataIntegration.Providers.Provider"), AddInLabel("User Provider"), AddInDescription("User provider"), AddInIgnore(false)]
    public class UserProvider : SqlProvider.SqlProvider, IDestination, IDropDownOptions, ISource
    {
        private Job _job = null;
        private UserDestinationWriter Writer = null;
        public bool IsFirstJobRun = true;

        [AddInParameter("Export users created and edited since last export"), AddInParameterEditor(typeof(YesNoParameterEditor), ""), AddInParameterGroup("Source")]
        public virtual bool ExportNotExportedUsers { get; set; }

        [AddInParameter("Export users that have been added or edited after"), AddInParameterEditor(typeof(YesNoParameterEditor), ""), AddInParameterGroup("Source")]
        public virtual bool ExportNotExportedAfter { get; set; }

        private DateTime _exportNotExportedAfterDate = DateTime.Now;
        [AddInParameter("Not exported after"), AddInParameterEditor(typeof(DateTimeParameterEditor), ""), AddInParameterGroup("Source")]
        public virtual DateTime ExportNotExportedAfterDate
        {
            get
            {
                return _exportNotExportedAfterDate;
            }
            set
            {
                _exportNotExportedAfterDate = value;
            }
        }

        [AddInParameter("User key field"), AddInParameterEditor(typeof(DropDownParameterEditor), "none=true;SortBy=Key;"), AddInParameterGroup("Destination")]
        public string UserKeyField { get; set; }

        [AddInParameter("Remove missing users"), AddInParameterEditor(typeof(YesNoParameterEditor), ""), AddInParameterGroup("Destination")]
        public bool RemoveMissingUsers { get; set; }

        [AddInParameter("Deactivate missing users"), AddInParameterEditor(typeof(YesNoParameterEditor), ""), AddInParameterGroup("Destination")]
        public bool DeactivateMissingUsers { get; set; }

        [AddInParameter("Generate passwords for users"), AddInParameterEditor(typeof(YesNoParameterEditor), ""), AddInParameterGroup("Destination")]
        public bool GenerateUserPasswords { get; set; }

        [AddInParameter("Encrypt passwords"), AddInParameterEditor(typeof(YesNoParameterEditor), ""), AddInParameterGroup("Destination")]
        public bool EncryptUserPasswords { get; set; }

        [AddInParameter("Delete users only from groups that are imported to"), AddInParameterEditor(typeof(YesNoParameterEditor), ""), AddInParameterGroup("Destination")]
        public bool DeleteOnlyFromGroupsThatAreImportedTo { get; set; }

        [AddInParameter("Remove missing groups"), AddInParameterEditor(typeof(YesNoParameterEditor), ""), AddInParameterGroup("Destination")]
        public bool RemoveMissingGroups { get; set; }

        [AddInParameter("Remove missing impersonation"), AddInParameterEditor(typeof(YesNoParameterEditor), ""), AddInParameterGroup("Destination")]
        public bool RemoveMissingImpersonation { get; set; }

        [AddInParameter("Remove missing addresses"), AddInParameterEditor(typeof(YesNoParameterEditor), ""), AddInParameterGroup("Destination")]
        public bool RemoveMissingAddresses { get; set; }

        [AddInParameter("Discard duplicates"), AddInParameterEditor(typeof(YesNoParameterEditor), ""), AddInParameterGroup("Destination")]
        public override bool DiscardDuplicates { get; set; }

        [AddInParameter("Use email for username"), AddInParameterEditor(typeof(YesNoParameterEditor), ""), AddInParameterGroup("Destination")]
        public bool UseEmailForUsername { get; set; }

        [AddInParameter("Destination group"), AddInParameterEditor(typeof(UserGroupParameterEditor), ""), AddInParameterGroup("Destination")]
        public string DestinationGroup { get; set; }

        [AddInParameter("Import users belong exactly import groups"), AddInParameterEditor(typeof(YesNoParameterEditor), ""), AddInParameterGroup("Destination")]
        public bool ImportUsersBelongExactlyImportGroups { get; set; }


        //Only UI Caption
        [AddInParameter("E-mail configuration:"), AddInParameterEditor(typeof(LabelParameterEditor), ""), AddInParameterGroup("Destination")]
        public string EmailConfigurationLabel { get { return " "; } }

        [AddInParameter("Mail Subject"), AddInParameterEditor(typeof(TextParameterEditor), ""), AddInParameterGroup("Destination")]
        public string MailSubject { get; set; }

        [AddInParameter("Sender E-mail"), AddInParameterEditor(typeof(TextParameterEditor), ""), AddInParameterGroup("Destination")]
        public string SenderEmail { get; set; }

        [AddInParameter("E-mail Template"), AddInParameterEditor(typeof(TemplateParameterEditor), "folder=Templates/UserManagement/UserProvider"), AddInParameterGroup("Destination")]
        public string EmailTemplate { get; set; }

        public bool AllowEmail { get; set; }

        [AddInParameter("Repositories index update"), AddInParameterEditor(typeof(DropDownParameterEditor), "multiple=true;none=true;Tooltip=Index update might affect on slower perfomance"), AddInParameterGroup("Destination")]
        public string RepositoriesIndexUpdate { get; set; }

        #region HideParameters
        [AddInParameter("Source server"), AddInParameterEditor(typeof(TextParameterEditor), ""), AddInParameterGroup("hidden")]
        public override string SourceServer
        {
            get { return Server; }
            set { Server = value; }
        }
        [AddInParameter("Destination server"), AddInParameterEditor(typeof(TextParameterEditor), ""), AddInParameterGroup("hidden")]
        public override string DestinationServer
        {
            get { return Server; }
            set { Server = value; }
        }
        [AddInParameter("Use integrated security to connect to source server"), AddInParameterEditor(typeof(Extensibility.Editors.YesNoParameterEditor), ""), AddInParameterGroup("hidden")]
        public override bool SourceServerSSPI
        {
            get;
            set;
        }
        [AddInParameter("Use integrated security to connect to destination server"), AddInParameterEditor(typeof(Extensibility.Editors.YesNoParameterEditor), ""), AddInParameterGroup("hidden")]
        public override bool DestinationServerSSPI
        {
            get;
            set;
        }
        [AddInParameter("Sql source server username"), AddInParameterEditor(typeof(TextParameterEditor), ""), AddInParameterGroup("hidden")]
        public override string SourceUsername
        {
            get { return Username; }
            set { Username = value; }
        }
        [AddInParameter("Sql destination server username"), AddInParameterEditor(typeof(TextParameterEditor), ""), AddInParameterGroup("hidden")]
        public override string DestinationUsername
        {
            get { return Username; }
            set { Username = value; }
        }
        [AddInParameter("Sql source server password"), AddInParameterEditor(typeof(TextParameterEditor), ""), AddInParameterGroup("hidden")]
        public override string SourcePassword
        {
            get { return Password; }
            set { Password = value; }
        }
        [AddInParameter("Sql destination server password"), AddInParameterEditor(typeof(TextParameterEditor), ""), AddInParameterGroup("hidden")]
        public override string DestinationPassword
        {
            get { return Password; }
            set { Password = value; }
        }
        [AddInParameter("Sql source database"), AddInParameterEditor(typeof(TextParameterEditor), ""), AddInParameterGroup("hidden")]
        public override string SourceDatabase
        {
            get { return Catalog; }
            set { Catalog = value; }
        }
        [AddInParameter("Sql source connection string"), AddInParameterEditor(typeof(TextParameterEditor), ""), AddInParameterGroup("hidden")]
        public override string SourceConnectionString
        {
            get { return ManualConnectionString; }
            set { ManualConnectionString = value; }
        }
        [AddInParameter("Sql destination connection string"), AddInParameterEditor(typeof(TextParameterEditor), ""), AddInParameterGroup("hidden")]
        public override string DestinationConnectionString
        {
            get { return ManualConnectionString; }
            set { ManualConnectionString = value; }
        }
        [AddInParameter("Sql destination server password"), AddInParameterEditor(typeof(TextParameterEditor), ""), AddInParameterGroup("hidden")]
        public override string DestinationDatabase
        {
            get { return Catalog; }
            set { Catalog = value; }
        }
        #endregion

        protected override SqlConnection Connection
        {
            get { return connection ?? (connection = (SqlConnection)Database.CreateConnection()); }
            set { connection = value; }
        }

        private static Dictionary<string, string> _groupDestinationColumnMapping = new Dictionary<string, string>()
        {
            {"AccessGroupGroupName", "AccessUserUserName"},
            {"AccessGroupParentGroupName", "AccessUserParentID"}
        };
        List<string> _columnsWithoutAccessUserPrefix = new List<string>();

        public UserProvider(string connectionString)
        {
            SqlConnectionString = connectionString;
            Connection = new SqlConnection(connectionString);
            DiscardDuplicates = false;
        }

        public UserProvider()
        {
            if (string.IsNullOrEmpty(UserKeyField))
                UserKeyField = "Auto";
            DiscardDuplicates = false;
        }
        public override Schema GetOriginalSourceSchema()
        {
            Schema result = base.GetOriginalSourceSchema();
            Table accessUserTable = null;
            List<string> tablestToKeep = new List<string> { "AccessUser", "AccessUserAddress", "AccessUserSecondaryRelation" };
            SystemFieldCollection systemFields = SystemField.GetSystemFields("AccessUser");
            if (systemFields != null && systemFields.Count > 0)
            {
                tablestToKeep.Add("SystemFieldValue");
            }
            List<Table> tablesToRemove = new List<Table>();
            foreach (Table table in result.GetTables())
            {
                if (!tablestToKeep.Contains(table.Name))
                    tablesToRemove.Add(table);
            }
            foreach (Table table in tablesToRemove)
            {
                result.RemoveTable(table);
            }
            foreach (Table table in result.GetTables())
            {
                switch (table.Name)
                {
                    case "AccessUser":
                        accessUserTable = table;
                        //set key for AccessUserTable
                        if (!string.IsNullOrEmpty(UserKeyField))
                        {
                            Column keyColumn = table.Columns.Find(c => c.Name == UserKeyField);
                            if (keyColumn != null)
                            {
                                //remove existing primary keys taken from DB table
                                foreach (Column c in table.Columns)
                                    c.IsPrimaryKey = false;
                                keyColumn.IsPrimaryKey = true;
                            }
                        }
                        break;
                    case "AccessUserAddress":
                        ChangeTableColumnType(table, "AccessUserAddressUserID", "nvarchar", false);
                        break;
                    case "AccessUserSecondaryRelation":
                        ChangeTableColumnType(table, "AccessUserSecondaryRelationUserID", "nvarchar", true);
                        ChangeTableColumnType(table, "AccessUserSecondaryRelationSecondaryUserID", "nvarchar", true);
                        break;
                    case "SystemFieldValue":
                        Column SystemFieldValueTableNameColumn = table.Columns.FirstOrDefault(c => c.Name == "SystemFieldValueTableName");
                        if (SystemFieldValueTableNameColumn != null)
                        {
                            table.Columns.Remove(SystemFieldValueTableNameColumn);
                        }
                        ChangeTableColumnType(table, "SystemFieldValueItemId", "nvarchar", true);
                        break;
                }
            }

            AddGroupTableToSchema(result, accessUserTable);
            ChangeTableColumnType(result.GetTables().FirstOrDefault(t => t.Name == "AccessUserGroup"), "AccessGroupParentGroupName", "nvarchar", false);

            accessUserTable.Columns.Remove(accessUserTable.Columns.Find(c => c.Name == "AccessUserParentID"));

            return result;
        }

        public override Schema GetOriginalDestinationSchema()
        {
            return GetOriginalSourceSchema();
        }

        public override void OverwriteSourceSchemaToOriginal()
        {
            Schema = GetOriginalSourceSchema();
        }

        public override void OverwriteDestinationSchemaToOriginal()
        {
            Schema = GetOriginalSourceSchema();
        }

        public override Schema GetSchema()
        {
            if (Schema == null)
            {
                Schema = GetOriginalSourceSchema();
            }
            return Schema;
        }

        public UserProvider(XmlNode xmlNode)
        {
            foreach (XmlNode node in xmlNode.ChildNodes)
            {
                switch (node.Name)
                {
                    case "SqlConnectionString":
                        if (node.HasChildNodes)
                        {
                            SqlConnectionString = node.FirstChild.Value;
                            Connection = new SqlConnection(SqlConnectionString);
                        }
                        break;
                    case "Schema":
                        Schema = new Schema(node);
                        break;
                    case "UserKeyField":
                        if (node.FirstChild != null && node.FirstChild.Value != null)
                            UserKeyField = node.FirstChild.Value;
                        break;
                    case "RemoveMissingUsers":
                        RemoveMissingUsers = node.FirstChild.Value == "True";
                        break;
                    case "DeactivateMissingUsers":
                        DeactivateMissingUsers = node.FirstChild.Value == "True";
                        break;
                    case "GenerateUserPasswords":
                        GenerateUserPasswords = node.FirstChild.Value == "True";
                        break;
                    case "EncryptUserPasswords":
                        EncryptUserPasswords = node.FirstChild.Value == "True";
                        break;
                    case "RemoveMissingGroups":
                        RemoveMissingGroups = node.FirstChild.Value == "True";
                        break;
                    case "RemoveMissingImpersonation":
                        RemoveMissingImpersonation = node.FirstChild.Value == "True";
                        break;
                    case "RemoveMissingAddresses":
                        RemoveMissingAddresses = node.FirstChild.Value == "True";
                        break;
                    case "UseEmailForUsername":
                        UseEmailForUsername = node.FirstChild.Value == "True";
                        break;
                    case "DestinationFolder":
                        if (node.FirstChild != null && node.FirstChild.Value != null)
                            DestinationGroup = node.FirstChild.Value;
                        break;
                    case "MailSubject":
                        if (node.FirstChild != null && node.FirstChild.Value != null)
                            MailSubject = node.FirstChild.Value;
                        break;
                    case "SenderEmail":
                        if (node.FirstChild != null && node.FirstChild.Value != null)
                            SenderEmail = node.FirstChild.Value;
                        break;
                    case "EmailTemplate":
                        if (node.FirstChild != null && node.FirstChild.Value != null)
                            EmailTemplate = node.FirstChild.Value;
                        break;
                    case "ExportNotExportedUsers":
                        if (node.FirstChild != null && node.FirstChild.Value != null)
                            ExportNotExportedUsers = node.FirstChild.Value == "True";
                        break;
                    case "ExportNotExportedAfter":
                        if (node.FirstChild != null && node.FirstChild.Value != null)
                            ExportNotExportedAfter = node.FirstChild.Value == "True";
                        break;
                    case "ExportNotExportedAfterDate":
                        if (node.FirstChild != null && node.FirstChild.Value != null)
                        {
                            DateTime dt;
                            if (DateTime.TryParse(node.FirstChild.Value, out dt))
                                ExportNotExportedAfterDate = dt;
                        }
                        break;
                    case "DeleteOnlyFromGroupsThatAreImportedTo":
                        DeleteOnlyFromGroupsThatAreImportedTo = node.FirstChild.Value == "True";
                        break;
                    case "DiscardDuplicates":
                        if (node.HasChildNodes)
                            DiscardDuplicates = node.FirstChild.Value == "True";
                        break;
                    case "ImportUsersBelongExactlyImportGroups":
                        if (node.HasChildNodes)
                            ImportUsersBelongExactlyImportGroups = node.FirstChild.Value == "True";
                        break;
                    case "RepositoriesIndexUpdate":
                        if (node.HasChildNodes)
                            RepositoriesIndexUpdate = node.FirstChild.Value;
                        break;
                    case "SkipFailingRows":
                        if (node.HasChildNodes)
                            SkipFailingRows = node.FirstChild.Value == "True";
                        break;
                }
            }
        }

        public override string ValidateDestinationSettings()
        {
            string result = string.Empty;
            if (!string.IsNullOrEmpty(EmailTemplate))
            {
                if (string.IsNullOrEmpty(SenderEmail))
                {
                    result = "Sender e-mail can not be empty. ";
                }
                else if (!Core.Helpers.StringHelper.IsValidEmailAddress(SenderEmail))
                {
                    result = "Sender e-mail is not valid. ";
                }
                if (string.IsNullOrEmpty(MailSubject))
                {
                    result += "Mail subject can not be empty. ";
                }
                result = result.TrimEnd(new char[] { ' ' });
            }
            return result;
        }
        public override string ValidateSourceSettings()
        {
            return null;
        }
        public new virtual void SaveAsXml(XmlTextWriter xmlTextWriter)
        {
            xmlTextWriter.WriteElementString("SqlConnectionString", SqlConnectionString);
            xmlTextWriter.WriteElementString("UserKeyField", UserKeyField);
            xmlTextWriter.WriteElementString("RemoveMissingUsers", RemoveMissingUsers.ToString(CultureInfo.CurrentCulture));
            xmlTextWriter.WriteElementString("DeactivateMissingUsers", DeactivateMissingUsers.ToString(CultureInfo.CurrentCulture));
            xmlTextWriter.WriteElementString("GenerateUserPasswords", GenerateUserPasswords.ToString(CultureInfo.CurrentCulture));
            xmlTextWriter.WriteElementString("EncryptUserPasswords", EncryptUserPasswords.ToString(CultureInfo.CurrentCulture));
            xmlTextWriter.WriteElementString("RemoveMissingGroups", RemoveMissingGroups.ToString(CultureInfo.CurrentCulture));
            xmlTextWriter.WriteElementString("RemoveMissingImpersonation", RemoveMissingImpersonation.ToString(CultureInfo.CurrentCulture));
            xmlTextWriter.WriteElementString("RemoveMissingAddresses", RemoveMissingAddresses.ToString(CultureInfo.CurrentCulture));
            xmlTextWriter.WriteElementString("UseEmailForUsername", UseEmailForUsername.ToString(CultureInfo.CurrentCulture));
            xmlTextWriter.WriteElementString("DestinationFolder", DestinationGroup);
            xmlTextWriter.WriteElementString("MailSubject", MailSubject);
            xmlTextWriter.WriteElementString("SenderEmail", SenderEmail);
            xmlTextWriter.WriteElementString("EmailTemplate", EmailTemplate);
            xmlTextWriter.WriteElementString("ExportNotExportedUsers", ExportNotExportedUsers.ToString(CultureInfo.CurrentCulture));
            xmlTextWriter.WriteElementString("ExportNotExportedAfter", ExportNotExportedAfter.ToString(CultureInfo.CurrentCulture));
            xmlTextWriter.WriteElementString("ExportNotExportedAfterDate", ExportNotExportedAfterDate.ToString(CultureInfo.CurrentCulture));
            xmlTextWriter.WriteElementString("DeleteOnlyFromGroupsThatAreImportedTo", DeleteOnlyFromGroupsThatAreImportedTo.ToString(CultureInfo.CurrentCulture));
            xmlTextWriter.WriteElementString("DiscardDuplicates", DiscardDuplicates.ToString(CultureInfo.CurrentCulture));
            xmlTextWriter.WriteElementString("ImportUsersBelongExactlyImportGroups", ImportUsersBelongExactlyImportGroups.ToString(CultureInfo.CurrentCulture));
            xmlTextWriter.WriteElementString("RepositoriesIndexUpdate", RepositoriesIndexUpdate);
            xmlTextWriter.WriteElementString("SkipFailingRows", SkipFailingRows.ToString(CultureInfo.CurrentCulture));
            GetSchema().SaveAsXml(xmlTextWriter);
        }
        public override void UpdateSourceSettings(ISource source)
        {
            UserProvider newProvider = (UserProvider)source;
            UserKeyField = newProvider.UserKeyField;
            RemoveMissingUsers = newProvider.RemoveMissingUsers;
            DeactivateMissingUsers = newProvider.DeactivateMissingUsers;
            GenerateUserPasswords = newProvider.GenerateUserPasswords;
            EncryptUserPasswords = newProvider.EncryptUserPasswords;
            RemoveMissingGroups = newProvider.RemoveMissingGroups;
            RemoveMissingImpersonation = newProvider.RemoveMissingImpersonation;
            RemoveMissingAddresses = newProvider.RemoveMissingAddresses;
            UseEmailForUsername = newProvider.UseEmailForUsername;
            DestinationGroup = newProvider.DestinationGroup;
            MailSubject = newProvider.MailSubject;
            SenderEmail = newProvider.SenderEmail;
            EmailTemplate = newProvider.EmailTemplate;
            ExportNotExportedUsers = newProvider.ExportNotExportedUsers;
            ExportNotExportedAfter = newProvider.ExportNotExportedAfter;
            ExportNotExportedAfterDate = newProvider.ExportNotExportedAfterDate;
            DeleteOnlyFromGroupsThatAreImportedTo = newProvider.DeleteOnlyFromGroupsThatAreImportedTo;
            DiscardDuplicates = newProvider.DiscardDuplicates;
            ImportUsersBelongExactlyImportGroups = newProvider.ImportUsersBelongExactlyImportGroups;
            RepositoriesIndexUpdate = newProvider.RepositoriesIndexUpdate;
            SkipFailingRows = newProvider.SkipFailingRows;
            base.UpdateSourceSettings(source);
        }
        public override void UpdateDestinationSettings(IDestination destination)
        {
            ISource newProvider = (ISource)destination;
            UpdateSourceSettings(newProvider);
        }
        public override string Serialize()
        {
            XDocument document = new XDocument(new XDeclaration("1.0", "utf-8", string.Empty));
            XElement root = new XElement("Parameters");
            if (!string.IsNullOrEmpty(UserKeyField))
            {
                root.Add(CreateParameterNode(GetType(), "User key field", UserKeyField.ToString(CultureInfo.CurrentCulture)));
            }
            root.Add(CreateParameterNode(GetType(), "Remove missing users", RemoveMissingUsers.ToString(CultureInfo.CurrentCulture)));
            root.Add(CreateParameterNode(GetType(), "Deactivate missing users", DeactivateMissingUsers.ToString(CultureInfo.CurrentCulture)));
            root.Add(CreateParameterNode(GetType(), "Generate passwords for users", GenerateUserPasswords.ToString(CultureInfo.CurrentCulture)));
            root.Add(CreateParameterNode(GetType(), "Encrypt passwords", EncryptUserPasswords.ToString(CultureInfo.CurrentCulture)));
            root.Add(CreateParameterNode(GetType(), "Remove missing groups", RemoveMissingGroups.ToString(CultureInfo.CurrentCulture)));
            root.Add(CreateParameterNode(GetType(), "Remove missing impersonation", RemoveMissingImpersonation.ToString(CultureInfo.CurrentCulture)));
            root.Add(CreateParameterNode(GetType(), "Remove missing addresses", RemoveMissingAddresses.ToString(CultureInfo.CurrentCulture)));
            root.Add(CreateParameterNode(GetType(), "Use email for username", UseEmailForUsername.ToString(CultureInfo.CurrentCulture)));
            root.Add(CreateParameterNode(GetType(), "Destination group", DestinationGroup));
            if (!string.IsNullOrEmpty(MailSubject))
                root.Add(CreateParameterNode(GetType(), "Mail Subject", MailSubject.ToString(CultureInfo.CurrentCulture)));
            if (!string.IsNullOrEmpty(SenderEmail))
                root.Add(CreateParameterNode(GetType(), "Sender E-mail", SenderEmail.ToString(CultureInfo.CurrentCulture)));
            if (!string.IsNullOrEmpty(EmailTemplate))
                root.Add(CreateParameterNode(GetType(), "E-mail Template", EmailTemplate.ToString(CultureInfo.CurrentCulture)));

            root.Add(CreateParameterNode(GetType(), "Export users created and edited since last export", ExportNotExportedUsers.ToString(CultureInfo.CurrentCulture)));
            root.Add(CreateParameterNode(GetType(), "Export users that have been added or edited after", ExportNotExportedAfter.ToString(CultureInfo.CurrentCulture)));
            root.Add(CreateParameterNode(GetType(), "Not exported after", ExportNotExportedAfterDate.ToString(CultureInfo.CurrentCulture)));
            root.Add(CreateParameterNode(GetType(), "Delete users only from groups that are imported to", DeleteOnlyFromGroupsThatAreImportedTo.ToString(CultureInfo.CurrentCulture)));
            root.Add(CreateParameterNode(GetType(), "Discard duplicates", DiscardDuplicates.ToString()));
            root.Add(CreateParameterNode(GetType(), "Import users belong exactly import groups", ImportUsersBelongExactlyImportGroups.ToString(CultureInfo.CurrentCulture)));
            root.Add(CreateParameterNode(GetType(), "Repositories index update", RepositoriesIndexUpdate));
            root.Add(CreateParameterNode(GetType(), "Persist successful rows and skip failing rows", SkipFailingRows.ToString()));

            document.Add(root);

            return document.ToString();
        }

        public Hashtable GetOptions(string name)
        {
            var options = new Hashtable();
            if (name == "Repositories index update")
            {
                options = GetRepositoriesIndexes();
            }
            else
            {
                var accessuserTable = GetSchema().GetTables().Find(t => t.Name == "AccessUser");
                if (accessuserTable != null)
                {
                    foreach (Column column in accessuserTable.Columns)
                    {
                        options.Add(column.Name, column.Name);
                    }
                    if (!options.ContainsKey("Auto"))
                    {
                        options.Add("Auto", "Auto");
                    }
                }
            }
            return options;
        }

        private IEnumerable<Mapping> GetMappingsByName(MappingCollection collection, string name)
        {
            return collection.FindAll(map => map.DestinationTable != null && map.DestinationTable.Name == name);
        }

        private void OrderTablesInJob(Job job)
        {
            MappingCollection tables = new MappingCollection();
            var mappings = GetMappingsByName(job.Mappings, "AccessUserGroup");
            if (mappings != null)
                tables.AddRange(mappings);

            mappings = GetMappingsByName(job.Mappings, "AccessUser");
            if (mappings != null)
                tables.AddRange(mappings);

            mappings = GetMappingsByName(job.Mappings, "AccessUserAddress");
            if (mappings != null)
                tables.AddRange(mappings);

            mappings = GetMappingsByName(job.Mappings, "AccessUserSecondaryRelation");
            if (mappings != null)
                tables.AddRange(mappings);

            mappings = GetMappingsByName(job.Mappings, "SystemFieldValue");
            if (mappings != null)
                tables.AddRange(mappings);

            job.Mappings = tables;
        }

        public override bool RunJob(Job job)
        {
            ReplaceMappingConditionalsWithValuesFromRequest(job);
            if (IsFirstJobRun)
            {
                OrderTablesInJob(job);
            }
            SqlTransaction sqlTransaction = null;
            if (Connection.State.ToString() != "Open")
                Connection.Open();

            Dictionary<string, object> sourceRow = null;
            bool isReadFromSourceFinished = IsReadingSourceXmlFinished(job);
            Exception exception = null;
            try
            {
                UpdateUserGroupMapping(job.Mappings);
                if (IsFirstJobRun)
                {
                    Writer = new UserDestinationWriter(job, Connection,
                        RemoveMissingUsers, GenerateUserPasswords, EncryptUserPasswords, RemoveMissingGroups, UseEmailForUsername,
                        UserKeyField, MailSubject, SenderEmail, EmailTemplate, AllowEmail,
                        string.IsNullOrEmpty(DestinationGroup) ? DestinationGroup : DestinationGroup.Replace("GRP_", ""),
                        DeleteOnlyFromGroupsThatAreImportedTo, Logger, DiscardDuplicates, ImportUsersBelongExactlyImportGroups,
                        RemoveMissingImpersonation, RemoveMissingAddresses, DeactivateMissingUsers, _groupDestinationColumnMapping,
                        SkipFailingRows);
                }
                else if (Writer == null)
                {
                    throw new Exception($"Can not find UserDestinationWriter.");
                }
                foreach (Mapping mapping in job.Mappings)
                {
                    if (mapping.Active && mapping.GetColumnMappings().Count > 0)
                    {
                        Logger.Log("Importing data to table: " + mapping.DestinationTable.Name);

                        bool? optionValue = mapping.GetOptionValue("DiscardDuplicates");
                        bool discardDuplicates = optionValue.HasValue ? optionValue.Value : DiscardDuplicates;

                        using (var reader = job.Source.GetReader(mapping))
                        {
                            while (!reader.IsDone())
                            {
                                sourceRow = reader.GetNext();
                                ProcessInputRow(mapping, sourceRow);
                                Writer.Write(sourceRow, mapping, discardDuplicates);
                            }
                        }
                    }
                }
                sourceRow = null;
                if (isReadFromSourceFinished)
                {
                    Writer.FinishWriting();
                    sqlTransaction = Connection.BeginTransaction();
                    Writer.MoveDataToMainTables(sqlTransaction);
                    Writer.DeleteExcessFromMainTable(sqlTransaction);
                    sqlTransaction.Commit();
                    Writer.SendUserPasswords();
                    if (Writer.RowsAffected > 0)
                    {
                        //Clear group cache for refreshing users in the groups they were imported
                        Group.ClearCache();
                    }
                    UnifiedPermissionService service = new UnifiedPermissionService();
                    foreach (string id in Writer.UpdatedUsers)
                    {
                        service.ClearUserCache(id);
                    }
                    UpdateIndex(job);
                }
            }
            catch (Exception ex)
            {
                exception = ex;
                string msg = ex.Message;
                LogManager.System.GetLogger(LogCategory.Application, "Dataintegration").Error($"{GetType().Name} error: {ex.Message} Stack: {ex.StackTrace}", ex);

                if (ex.Message.Contains("Subquery returned more than 1 value"))
                    msg += System.Environment.NewLine + "This error usually indicates user duplicates on the source column mapped to the selected option from User Key Field drop-down.";

                if (ex.Message.Contains("Bulk copy failures"))
                {
                    Logger.Log("Job Failed with the following message:");
                    BulkCopyHelper.LogFailedRows(Logger, msg);
                }
                else
                {
                    if (sourceRow != null && !ex.Message.Contains("User key field"))
                        msg += GetFailedSourceRowMessage(sourceRow);

                    Logger.Error("Job Failed with the following message: " + msg, ex);
                }

                if (sqlTransaction != null)
                    sqlTransaction.Rollback();
                return false;
            }
            finally
            {
                if (exception != null || isReadFromSourceFinished)
                {
                    if (Writer != null)
                        Writer.Close();
                }
                sourceRow = null;
            }
            if (IsFirstJobRun)
            {
                IsFirstJobRun = false;
            }
            return true;
        }

        public new ISourceReader GetReader(Mapping mapping)
        {
            return new UserSourceReader(mapping, Connection, ExportNotExportedUsers, ExportNotExportedAfter, ExportNotExportedAfterDate);
        }

        public override void LoadSettings(Job job)
        {
            this._job = job;
            OrderTablesInJob(job);
        }

        public new void Close()
        {
            if (_job != null && _job.Result == JobResult.Completed)
                UserSourceReader.UpdateExportedDataInDb(connection);

            base.Close();
        }

        private void UpdateUserGroupMapping(MappingCollection jobMappings)
        {
            foreach (Mapping mapping in jobMappings)
            {
                if (mapping.DestinationTable.Name == "AccessUserGroup")
                {
                    //update Group mapping to be used for insert to AccessUser table
                    foreach (Column c in mapping.DestinationTable.Columns)
                    {
                        if (!_columnsWithoutAccessUserPrefix.Contains(c.Name))
                        {
                            c.Name = GetOriginalColumnNameForGroups(c.Name);
                        }
                    }
                    foreach (ColumnMapping cm in mapping.GetColumnMappings())
                    {
                        if (!_columnsWithoutAccessUserPrefix.Contains(cm.DestinationColumn.Name))
                        {
                            cm.DestinationColumn.Name = GetOriginalColumnNameForGroups(cm.DestinationColumn.Name);
                        }
                    }
                }
            }
        }

        internal static string GetOriginalColumnNameForGroups(string columnName)
        {
            string ret = columnName;

            if (_groupDestinationColumnMapping.ContainsKey(columnName))
            {
                ret = _groupDestinationColumnMapping[columnName];
            }
            else
            {
                ret = columnName.Replace("AccessGroup", "AccessUser");
            }

            return ret;
        }

        private void AddGroupTableToSchema(Schema schema, Table accessUserTable)
        {
            Dictionary<string, string> destinationReversedMapping = ReverseDictionary(_groupDestinationColumnMapping);
            Table groupTable = schema.AddNewTable("AccessUserGroup", accessUserTable.SqlSchema);
            foreach (Column c in accessUserTable.Columns)
            {
                if (c.Name.StartsWith("AccessUser"))
                {
                    string key = destinationReversedMapping.Keys.FirstOrDefault(k => k.ToLower() == c.Name.ToLower());
                    if (!string.IsNullOrEmpty(key))
                    {
                        groupTable.AddColumn(new SqlColumn(destinationReversedMapping[key], c.Type, ((SqlColumn)c).SqlDbType, groupTable, ((SqlColumn)c).Limit, ((SqlColumn)c).IsIdentity, c.IsPrimaryKey, false));
                    }
                    else
                    {
                        groupTable.AddColumn(new SqlColumn(c.Name.Replace("AccessUser", "AccessGroup"), c.Type, ((SqlColumn)c).SqlDbType, groupTable, ((SqlColumn)c).Limit, ((SqlColumn)c).IsIdentity, c.IsPrimaryKey, false));
                    }
                }
                else
                {
                    _columnsWithoutAccessUserPrefix.Add(c.Name);
                    groupTable.AddColumn(new SqlColumn(c.Name, c.Type, ((SqlColumn)c).SqlDbType, groupTable, ((SqlColumn)c).Limit, ((SqlColumn)c).IsIdentity, c.IsPrimaryKey, false));
                }
            }
        }

        private Dictionary<string, string> ReverseDictionary(Dictionary<string, string> dict)
        {
            Dictionary<string, string> ret = new Dictionary<string, string>();
            foreach (KeyValuePair<string, string> kvp in dict)
                if (!ret.ContainsKey(kvp.Value))
                    ret.Add(kvp.Value, kvp.Key);
            return ret;
        }

        private void ChangeTableColumnType(Table table, string columnName, string newColumnType, bool isPrimaryKey)
        {
            SqlColumn column = (SqlColumn)table.Columns.Find(c => c.Name.ToLower() == columnName.ToLower());
            if (column != null)
            {
                table.Columns.Remove(column);
                column = new SqlColumn(column.Name, newColumnType, table, -1, false, isPrimaryKey);
                table.Columns.Add(column);
            }
        }

        #region IDestination Members

        List<SchemaComparerResult> IDestination.CheckMapping(Mapping map)
        {
            return new List<SchemaComparerResult>();
        }

        #endregion

        public bool IsReadingSourceXmlFinished(Job job)
        {
            if (job.Source != null && job.Source is XmlProvider.XmlProvider)
            {
                return ((XmlProvider.XmlProvider)job.Source).ExportIsDone;
            }
            return true;
        }

        protected void UpdateIndex(Job job)
        {
            if (!string.IsNullOrEmpty(RepositoriesIndexUpdate))
            {
                UpdateIndexes(RepositoriesIndexUpdate.Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries).ToList());
            }
        }

        protected Hashtable GetRepositoriesIndexes()
        {
            Hashtable ret = new Hashtable();
            IRepositoryService repoService = ServiceLocator.Current.GetInstance<IRepositoryService>();
            if (repoService != null)
            {
                foreach (string repoName in repoService.GetRepositories())
                {
                    foreach (RepositoryItem repoItem in repoService.GetRepositoryItems(repoName).Where(ri => string.Equals(ri.TypeName, "Index", StringComparison.OrdinalIgnoreCase)))
                    {
                        var indexingService = ServiceLocator.Current.GetInstance<IIndexService>();
                        var index = indexingService.LoadIndex(repoName, repoItem.Name);
                        foreach (var build in index.Builds)
                        {
                            if (build.Value is Dynamicweb.Security.UserManagement.Indexing.UserIndexBuilder)
                            {
                                ret.Add(string.Concat(repoName, "-", repoItem.Name, "-", build.Key), string.Concat(repoName, "-", repoItem.Name.Substring(0, repoItem.Name.LastIndexOf(".")), "-", build.Key));
                            }
                        }
                    }
                }
            }
            return ret;
        }
    }
}
