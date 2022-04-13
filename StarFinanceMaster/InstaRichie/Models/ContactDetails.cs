using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using SQLite.Net.Attributes;

namespace StartFinance.Models
{
    public class ContactDetails
    {
        [PrimaryKey, AutoIncrement]
        public int ContactDetailsId { get; set; }

        [NotNull]
        public string ContactName { get; set; }

        public string DateOfBirth { get; set; }
        public string Phone { get; set; }
        public string Email { get; set; }
        public string Address { get; set; }

    }
}

     
