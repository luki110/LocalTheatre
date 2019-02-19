using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Linq;
using System.Web;

namespace LocalTheatreAssessmentLB.Models
{
    public class Comment
    {
        [Key]
        public int CommentId { get; set; }
        [Required]
        public string AuthorId { get; set; }
        [Required]
        public DateTime DateAdded { get; set; }
        [Required]
        public string Content { get; set; }
        [Required]
        public bool IsAproved { get; set; }

        ////navigational properties
        [ForeignKey("User")]
        public string UserId { get; set; }
        public virtual User User { get; set; }


    }
}