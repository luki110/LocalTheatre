using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Linq;
using System.Web;

namespace LocalTheatreAssessmentLB.Models
{
    public class Role
    {
        [Key]
        [Required]
        public string RoleId { get; set; }
        [Required]
        public string Name { get; set; }

        public Role()
        {
            Users = new List<User>();
        }

        //navigational properties
        public virtual ICollection<User> Users { get; set; }

    }
}