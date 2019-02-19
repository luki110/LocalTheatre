using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Linq;
using System.Web;

namespace LocalTheatreAssessmentLB.Models
{
    public class User : ApplicationUser
    {
        /// <summary>   Gets or sets the Date/Time of the registered at. </summary>
        ///
        /// <value> The registered at. </value>

        [Required]
        public DateTime RegisteredAt { get; set; }

        /// <summary>   Default constructor. </summary>
        ///
        /// <remarks>   Lukas, 30.01.2019. </remarks>

        public User()
        {
            Comments = new List<Comment>();
        }

        //navigational properties

        /// <summary>   Gets or sets the comments. </summary>
        ///
        /// <value> The comments. </value>

        public virtual ICollection<Comment> Comments { get; set; }

        /// <summary>   Gets or sets the identifier of the role. </summary>
        ///
        /// <value> The identifier of the role. </value>

        [ForeignKey("Role")]
        public string RoleId { get; set; }

        /// <summary>   Gets or sets the role. </summary>
        ///
        /// <value> The role. </value>

        public virtual Role Role { get; set; }
    }
}